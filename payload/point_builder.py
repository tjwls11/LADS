import re
import hashlib
from urllib.parse import urlparse
from collections import defaultdict


def _slug(url: str) -> str:
    path = urlparse(url).path.rstrip("/")
    name = path.split("/")[-1] if path else "root"
    return re.sub(r"[^a-zA-Z0-9]", "_", name)[:20] or "ep"


def _short_hash(value: str) -> str:
    return hashlib.sha1(value.encode("utf-8")).hexdigest()[:8]


def _safe_id(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]+", "_", value).strip("_")[:80] or "group"


def _group_examples(targets: list[dict]) -> dict[str, dict]:
    grouped: dict[str, dict] = defaultdict(lambda: {
        "value_examples": [],
        "url_examples": [],
        "option_examples": [],
    })

    for target in targets:
        url = target.get("action") or target.get("source_url", "")
        for param in target.get("params", []) or []:
            group_key = param.get("group_key")
            if not group_key:
                continue
            item = grouped[group_key]

            value = str(param.get("default_value") or "")
            if value not in item["value_examples"] and len(item["value_examples"]) < 5:
                item["value_examples"].append(value)

            if url and url not in item["url_examples"] and len(item["url_examples"]) < 5:
                item["url_examples"].append(url)

            options = param.get("options") or []
            if options and len(item["option_examples"]) < 3:
                item["option_examples"].append(options[:10])

    return grouped


# 입력 포인트 목록 -> 프롬프트에 필요한 구조로 변환
def build_points_from_targets(targets: list[dict]) -> list[dict]:
    points: list[dict] = []
    seen: set[str] = set()
    grouped_examples = _group_examples(targets)

    for target in targets:
        url = target.get("action") or target.get("source_url", "")
        method = (target.get("method") or "GET").upper()
        url_lower = url.lower()
        is_login = any(k in url_lower for k in ("login", "signin", "auth"))
        slug = _slug(url)
        target_key = _safe_id(str(target.get("id") or _short_hash(f"{method}:{url}")))

        all_params = target.get("params", [])
        injectable = [p for p in all_params if p.get("injectable")]

        for param in injectable:
            pname = param["name"]
            pname_lower = pname.lower()
            group_key = param.get("group_key") or f"{pname}:unknown:{method}:{param.get('field_type', 'unknown')}:{param.get('value_shape', 'unknown')}"
            key = f"{method}:{url}:{pname}:{group_key}"
            if key in seen:
                continue
            seen.add(key)

            base_params = {
                p["name"]: str(p.get("default_value") or "")
                for p in all_params
                if p["name"] != pname and p.get("default_value")
            }

            common = dict(
                url=url,
                method=method,
                param=pname,
                base_params=base_params,
                base_value=str(param.get("default_value") or ""),
                group_key=group_key,
                location=param.get("location") or target.get("type") or "unknown",
                field_type=param.get("field_type") or "unknown",
                value_shape=param.get("value_shape") or "unknown",
                enctype=target.get("enctype", ""),
                options=param.get("options") or [],
                value_examples=grouped_examples.get(group_key, {}).get("value_examples", []),
                url_examples=grouped_examples.get(group_key, {}).get("url_examples", []),
                option_examples=grouped_examples.get(group_key, {}).get("option_examples", []),
                db="MySQL",
                note=f"동적 발견 - {method} {url}",
            )

            if is_login:
                sqli_type = "sqli_login"
            elif any(k in pname_lower for k in ("sst", "order", "sort")):
                sqli_type = "sqli_orderby"
            elif any(k in pname_lower for k in ("sfl", "field", "col")):
                sqli_type = "sqli_field"
            else:
                sqli_type = "sqli_string"

            points.append({
                "name": f"sqli_{slug}_{target_key}_{_safe_id(group_key)}",
                "type": "string",
                "vuln_types": [sqli_type],
                **common,
            })

            if is_login or any(k in pname_lower for k in ("password", "passwd", "pw")):
                continue

            if any(k in pname_lower for k in ("subject", "title")):
                xss_type = "xss_subject"
            elif any(k in pname_lower for k in ("comment", "reply", "content")):
                xss_type = "xss_comment"
            elif "comment" in url_lower or "reply" in url_lower:
                xss_type = "xss_comment"
            elif method == "GET":
                xss_type = "xss_search"
            else:
                xss_type = "xss_content"

            points.append({
                "name": f"xss_{slug}_{target_key}_{_safe_id(group_key)}",
                "type": "stored_xss" if method == "POST" else "reflected_xss",
                "vuln_types": [xss_type],
                **common,
            })

    return points
