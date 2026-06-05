from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse
from attack.xss import get_all as xss_get_all
from attack.sqli import get_by_sql_context

_DESTRUCTIVE_SQL_RE = re.compile(
    r"\b(drop|delete|update|insert|alter|truncate|create|replace|rename|grant|revoke)\b",
    re.IGNORECASE,
)

SKIP_OPERATORS = {"and", "or", "move"}
SKIP_FIELD_TYPES = {"checkbox", "radio"}


def _is_destructive_payload(payload: str) -> bool:
    if not payload:
        return False
    return bool(_DESTRUCTIVE_SQL_RE.search(payload))


def _base_url(url: str) -> str:
    return urlparse(url)._replace(query="", fragment="").geturl()


def _guess_location(method: str) -> str:
    return "body" if method.upper() == "POST" else "query"


# SQLi 비교 요청의 그룹 이름을 생성함
def _sqli_task_group_id(method: str, action_url: str, param_name: str, category: str) -> str:
    return f"sqli:{method.upper()}:{_base_url(action_url)}:{param_name}:{category}"


_REC_TYPE_TO_CATEGORY: dict[str, str] = {
    "BOOLEAN":      "boolean",
    "ERROR_BASED":  "error",
    "TIME_BASED":   "time",
    "SQLI_ORDERBY": "order_by",
    "SQLI_FIELD":   "error",
    "SQLI_STRING":  "error",
}


def _sqli_category(vtype: str, rec_type: str | None) -> str | None:
    if rec_type and rec_type in _REC_TYPE_TO_CATEGORY:
        return _REC_TYPE_TO_CATEGORY[rec_type]
    vt = (vtype or "").lower()
    if "sqli" not in vt and "sql" not in vt:
        return None
    return "error"


# SQLi 페이로드의 비교 역할을 반환
def _sqli_role(category: str | None, payload: str | None) -> str | None:
    payload_text = str(payload or "").lower()
    if category == "boolean":
        if "1=2" in payload_text or "1=0" in payload_text or "false" in payload_text:
            return "false_attack"
        return "true_attack"
    if category == "time":
        if "sleep" in payload_text or "benchmark" in payload_text or "waitfor" in payload_text:
            return "delay_attack"
        return "time_baseline"
    if category == "order_by":
        if "extractvalue" in payload_text or "updatexml" in payload_text or "sleep" in payload_text:
            return "invalid_order"
        return "valid_order"
    if category == "error":
        return "attack"
    return None


# 공격성이 없는 비교 값을 생성함
def _safe_value(base_value: str) -> str:
    return f"{base_value}abcxyz" if base_value else "abcxyz"


def _should_skip(name: str, value: str, field_type: str) -> bool:
    if field_type in SKIP_FIELD_TYPES:
        return True
    v = str(value).strip()
    if re.match(r"^\d+$", v):
        return True
    if len(v) == 1:
        return True
    if v.lower() in SKIP_OPERATORS:
        return True
    return False


def _infer_types(field_type: str, action_url: str, param_name: str) -> list[str]:
    if field_type in ("text", "input", "email"):
        return ["sqli_string", "xss_search"]
    if field_type == "url_param":
        return ["sqli_string"]
    if field_type == "textarea":
        return ["xss_content"]
    if field_type == "select":
        return ["sqli_field"]
    if field_type == "hidden":
        return ["sqli_string"]
    return ["sqli_string"]



def _get_baseline_records_by_type(vtype: str) -> list[dict]:
    records: list[dict] = []
    if "xss" in vtype:
        from payload.baseline.xss import get_by_strength as xss_get_by_strength
        # get_by_strength("INSANE"): BODY+ATTR_VALUE+FILTER_BYPASS+SCRIPT_CONTEXT+STORED 전체 ~80개
        for bp in xss_get_by_strength("INSANE"):
            records.append({
                "vtype": vtype,
                "type": bp.get("type"),
                "family": "baseline_" + (bp.get("family") or ""),
                "payload": bp.get("payload"),
            })
    elif "sqli" in vtype:
        ctx_map = {
            "sqli_field":   "field_selector",
            "sqli_orderby": "orderby",
        }
        ctx = ctx_map.get(vtype, "like_string")
        for bp in get_by_sql_context(ctx, "INSANE"):
            records.append({
                "vtype": vtype,
                "type": bp.get("type"),
                "family": "baseline_" + (bp.get("family") or ""),
                "payload": bp.get("payload"),
            })
    return records


def build_tasks(
    targets: Any | None = None,
    base_cookie: dict | None = None,
    progress_callback=None,
) -> list[dict]:
    if not targets:
        return []

    out: list[dict] = []
    tid = 0
    seen_combos: set[tuple] = set()
    total = len(targets) if isinstance(targets, list) else 0

    for idx, target in enumerate(targets or []):
        if not isinstance(target, dict):
            continue

        action = target.get("action", "")
        source_url = target.get("source_url", "")
        method = (target.get("method") or "GET").upper()
        inject_location = _guess_location(method)
        all_params = target.get("params") or []

        if progress_callback:
            progress_callback(idx + 1, total)

        for param in all_params:
            if not isinstance(param, dict):
                continue
            if not param.get("injectable"):
                continue

            name = param.get("name", "")
            value = str(param.get("default_value") or "")
            field_type = param.get("field_type", "")

            if not name:
                continue
            if _should_skip(name, value, field_type):
                continue

            combo = (method, _base_url(action), name)
            if combo in seen_combos:
                continue
            seen_combos.add(combo)

            vuln_types = _infer_types(field_type, action, name)
            if not vuln_types:
                continue

            base_params = {
                p["name"]: str(p.get("default_value") or "")
                for p in all_params
                if isinstance(p, dict) and p.get("name") and p["name"] != name
            }

            used_payloads: set[str] = set()
            emitted_sqli_groups: set[str] = set()
            point_label = f"{_base_url(action).split('/')[-1]}_{name}"

            def _emit(payload: str, vtype: str, rec_type, family, rec_role=None, _label=point_label) -> None:
                nonlocal tid
                if not payload or payload in used_payloads:
                    return
                if _is_destructive_payload(payload):
                    print(f"[PROBE] skipped destructive payload: point={_label}")
                    return
                used_payloads.add(payload)
                category = _sqli_category(vtype, rec_type)
                task_group_id = None
                role = None
                if category:
                    task_group_id = _sqli_task_group_id(method, action, name, category)
                    role = rec_role or _sqli_role(category, payload)
                    if task_group_id not in emitted_sqli_groups:
                        emitted_sqli_groups.add(task_group_id)
                        for compare_role, compare_payload in (
                            ("original", value),
                            ("safe", _safe_value(value)),
                        ):
                            out.append({ # SQLi 비교 요청
                                "id": f"t{tid:06d}_r",
                                "point": _label,
                                "url": action,
                                "method": method,
                                "inject_location": inject_location,
                                "inject_param": name,
                                "inject_mode": "replace",
                                "base_params": base_params,
                                "base_cookies": base_cookie or {},
                                "base_value": value,
                                "payload": compare_payload,
                                "task_group_id": task_group_id,
                                "enctype": target.get("enctype", ""),
                                "meta": {
                                    "vuln_type": vtype,
                                    "type": rec_type,
                                    "family": family,
                                    "role": compare_role,
                                    "category": category,
                                },
                            })
                            tid += 1
                out.append({
                    "id": f"t{tid:06d}_r",
                    "point": _label,
                    "url": action,
                    "source_url": source_url,
                    "method": method,
                    "inject_location": inject_location,
                    "inject_param": name,
                    "inject_mode": "replace",
                    "base_params": base_params,
                    "base_cookies": base_cookie or {},
                    "base_value": value,
                    "payload": payload,
                    "task_group_id": task_group_id,
                    "enctype": target.get("enctype", ""),
                    "meta": {
                        "vuln_type": vtype,
                        "type": rec_type,
                        "family": family,
                        "role": role,
                        "category": category,
                    },
                })
                tid += 1

            for vtype in vuln_types:
                for rec in _get_baseline_records_by_type(vtype):
                    _emit(rec.get("payload"), vtype, rec.get("type"), rec.get("family"), rec.get("role"))

    return out
