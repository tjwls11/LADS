import json
import re
import sys
import os
from urllib.parse import unquote, urlparse

INPUT_FILE  = os.getenv("CRAWL_RESULT",  "results/crawl_result.json")
OUTPUT_FILE = os.getenv("TARGETS_FILE",  "results/targets.json")

# 인젝션 제외: CSRF/nonce 류 필드명
CSRF_RE = re.compile(r"(csrf|token|nonce|_token|authenticity|captcha)", re.IGNORECASE)

# 인젝션 제외: 의미 없는 버튼/파일 타입
SKIP_TYPES = {"submit", "button", "reset", "image", "file"}

BOOL_RE = re.compile(r"^(true|false|on|off|yes|no)$", re.IGNORECASE)
NUMBER_RE = re.compile(r"^[+-]?\d+(?:\.\d+)?$")
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$")


# --- 헬퍼 

def _injectable(name: str, field_type: str) -> bool:
    if field_type in SKIP_TYPES:
        return False
    if CSRF_RE.search(name):
        return False
    return True


def _base_url(url: str) -> str:
    return urlparse(url)._replace(query="", fragment="").geturl()


def _form_sig(action: str, method: str, names: list[str]) -> str:
    return f"{method}:{action}:{','.join(sorted(names))}"


def _url_sig(base: str, names: list[str]) -> str:
    return f"GET:{base}:{','.join(sorted(names))}"


# 크롤된 값의 겉모양 분류
def _value_shape(value: str, field_type: str, options: list) -> str:
    if options:
        return "enum"

    ft = (field_type or "").lower()
    if ft in {"checkbox", "radio"}:
        return "boolean_or_enum"

    raw = "" if value is None else str(value)
    if raw == "":
        return "empty"

    decoded = unquote(raw)
    lowered = decoded.lower()

    if TOKEN_RE.match(decoded):
        return "token_like"
    if EMAIL_RE.match(decoded):
        return "email_like"
    if lowered.startswith(("http://", "https://", "/")):
        return "url_or_path_like"
    if BOOL_RE.match(decoded):
        return "boolean_like"
    if NUMBER_RE.match(decoded):
        return "number_like"

    return "string"


# LLM 재사용 단위인 구조적 그룹 키 생성
def _group_key(name: str, location: str, method: str, field_type: str, value_shape: str) -> str:
    return ":".join([
        name or "unknown",
        location or "unknown",
        (method or "GET").upper(),
        field_type or "unknown",
        value_shape or "unknown",
    ])


# --- 핵심 분석
def build_targets(pages: list[dict]) -> list[dict]:
    targets: list[dict] = []
    seen:    set[str]   = set()
    tid = 0

    for page in pages:
        source = page["url"]

        # 1. URL 쿼리 파라미터
        qp = page.get("query_params", {})
        if qp:
            base = _base_url(source)
            params = []
            for name, vals in qp.items():
                default_value = vals[0] if vals else ""
                shape = _value_shape(default_value, "url_param", [])
                params.append({
                    "name":          name,
                    "location":      "query",
                    "method":        "GET",
                    "field_type":    "url_param",
                    "default_value": default_value,
                    "value_shape":   shape,
                    "group_key":     _group_key(name, "query", "GET", "url_param", shape),
                    "options":       [],
                    "injectable":    _injectable(name, "url_param"),
                })
            sig = _url_sig(base, [p["name"] for p in params])
            if sig not in seen:
                seen.add(sig)
                tid += 1
                targets.append({
                    "id":            f"url_{tid:04d}",
                    "type":          "url_param",
                    "source_url":    source,
                    "action":        base,
                    "method":        "GET",
                    "enctype":       "application/x-www-form-urlencoded",
                    "accessible_by": page.get("accessible_by", []),
                    "params":        params,
                })

        # 2. HTML Form
        for form in page.get("forms", []):
            params = []
            for f in form.get("fields", []):
                field_type = f.get("field_type", "text")
                name = f.get("name", "")
                if not name:
                    continue
                if field_type in SKIP_TYPES:
                    continue
                default_value = f.get("value", "")
                options = f.get("options", [])
                method = form.get("method", "GET").upper()
                shape = _value_shape(default_value, field_type, options)
                params.append({
                    "name":          name,
                    "location":      "form",
                    "method":        method,
                    "field_type":    field_type,
                    "default_value": default_value,
                    "value_shape":   shape,
                    "group_key":     _group_key(name, "form", method, field_type, shape),
                    "options":       options,
                    "injectable":    _injectable(name, field_type),
                })

            if not params:
                continue

            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            sig = _form_sig(action, method, [p["name"] for p in params])
            if sig not in seen:
                seen.add(sig)
                tid += 1
                needs_csrf = any(
                    not p["injectable"] and CSRF_RE.search(p["name"])
                    for p in params
                )
                targets.append({
                    "id":                 f"form_{tid:04d}",
                    "type":               "form",
                    "source_url":         source,
                    "action":             action,
                    "method":             method,
                    "enctype":            form.get("enctype", "application/x-www-form-urlencoded"),
                    "needs_csrf_refresh": needs_csrf,
                    "accessible_by":      page.get("accessible_by", []),
                    "params":             params,
                })

    return targets


if __name__ == "__main__":
    try:
        with open(INPUT_FILE, encoding="utf-8") as f:
            pages = json.load(f)
    except FileNotFoundError:
        print(f"[ERROR] {INPUT_FILE} 없음 — 먼저 crawler.py를 실행하세요.", file=sys.stderr)
        sys.exit(1)

    targets = build_targets(pages)

    parent = os.path.dirname(OUTPUT_FILE)
    if parent:
        os.makedirs(parent, exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(targets, f, ensure_ascii=False, indent=2)

    print(f"저장 완료: {OUTPUT_FILE}  ({len(targets)}개 타겟)")