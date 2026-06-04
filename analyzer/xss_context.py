from __future__ import annotations
import re

CTX_HTML_TEXT  = "html_text"
CTX_ATTR       = "attr"
CTX_URL_ATTR   = "url_attr"
CTX_EVENT_ATTR = "event_attr"
CTX_SCRIPT     = "script"
CTX_COMMENT    = "comment"
CTX_SAFE_TAG   = "safe_tag"
CTX_UNKNOWN    = "unknown"

# 이 태그 내부 반사는 브라우저가 실행하지 않음 (Dalfox SAFE_TAG_PATTERNS 동일)
SAFE_TAGS = ("textarea", "noscript", "xmp", "plaintext", "title", "style")

_URL_ATTRS = frozenset([
    "href", "src", "action", "formaction", "cite", "data",
    "manifest", "poster", "srcset", "longdesc", "background",
    "usemap", "codebase", "ping", "profile", "archive",
])

_DANGEROUS_SCHEMES = ("javascript:", "data:text/html", "data:image/svg", "vbscript:")

_EVENT_ATTR_RE = re.compile(r"\bon\w+\s*=\s*[\"']?$", re.IGNORECASE)
_URL_ATTR_RE = re.compile(
    r"\b(" + "|".join(re.escape(a) for a in sorted(_URL_ATTRS, key=len, reverse=True)) +
    r")\s*=\s*[\"']?[^\"'<>]*$",
    re.IGNORECASE,
)


def _build_safe_ranges(body_lower: str, body: str) -> list[tuple[int, int]]:
    safe_ranges: list[tuple[int, int]] = []
    for tag in SAFE_TAGS:
        open_tag  = f"<{tag}"
        close_tag = f"</{tag}>"
        search = 0
        while True:
            open_idx = body_lower.find(open_tag, search)
            if open_idx == -1:
                break
            tag_end = body.find(">", open_idx)
            if tag_end == -1:
                break
            content_start = tag_end + 1
            close_idx = body_lower.find(close_tag, content_start)
            if close_idx == -1:
                safe_ranges.append((content_start, len(body)))
                break
            safe_ranges.append((content_start, close_idx))
            search = close_idx + len(close_tag)
    return safe_ranges


# 특정 위치(idx)가 safe tag 내부에 있으면 True.
def is_idx_in_safe_context(body: str, idx: int) -> bool:
    if idx < 0:
        return False
    safe_ranges = _build_safe_ranges(body.lower(), body)
    return any(s <= idx < e for s, e in safe_ranges)


# payload의 모든 출현이 safe tag 내부에 있으면 True. Dalfox is_in_safe_context() 포트.
def is_in_safe_context(body: str, payload: str) -> bool:
    if not payload:
        return True
    body_lower    = body.lower()
    payload_lower = payload.lower()
    if payload_lower not in body_lower:
        return True

    safe_ranges = _build_safe_ranges(body_lower, body)
    if not safe_ranges:
        return False

    payload_len = len(payload_lower)
    search = 0
    while True:
        idx = body_lower.find(payload_lower, search)
        if idx == -1:
            break
        if not any(s <= idx and idx + payload_len <= e for s, e in safe_ranges):
            return False
        search = idx + 1
    return True


# marker_idx 위치의 HTML 컨텍스트를 반환한다.
def classify_context(body: str, marker_idx: int) -> str:
    if marker_idx < 0 or marker_idx >= len(body):
        return CTX_UNKNOWN

    body_lower = body.lower()

    comment_open = body.rfind("<!--", 0, marker_idx)
    if comment_open != -1:
        comment_close = body.find("-->", comment_open)
        if comment_close == -1 or comment_close > marker_idx:
            return CTX_COMMENT

    # raw text element(safe_tag / script): 먼저 열린 것이 이긴다 (HTML 파서 규칙)
    candidates: list[tuple[int, str]] = []

    for tag in SAFE_TAGS:
        pos = body_lower.rfind(f"<{tag}", 0, marker_idx)
        if pos == -1:
            continue
        tag_end = body.find(">", pos)
        if tag_end == -1 or tag_end >= marker_idx:
            continue
        close_pos = body_lower.find(f"</{tag}>", tag_end + 1)
        if close_pos == -1 or close_pos > marker_idx:
            candidates.append((pos, CTX_SAFE_TAG))

    script_pos = body_lower.rfind("<script", 0, marker_idx)
    if script_pos != -1:
        script_tag_end = body.find(">", script_pos)
        if script_tag_end != -1 and script_tag_end < marker_idx:
            script_close = body_lower.find("</script", script_tag_end + 1)
            if script_close == -1 or script_close > marker_idx:
                candidates.append((script_pos, CTX_SCRIPT))

    if candidates:
        return min(candidates, key=lambda x: x[0])[1]

    last_open  = body.rfind("<", 0, marker_idx)
    last_close = body.rfind(">", 0, marker_idx)
    if last_open != -1 and last_open > last_close:
        tag_content = body[last_open:marker_idx]
        if _EVENT_ATTR_RE.search(tag_content):
            return CTX_EVENT_ATTR
        if _URL_ATTR_RE.search(tag_content):
            return CTX_URL_ATTR
        return CTX_ATTR

    return CTX_HTML_TEXT


def context_has_dangerous_scheme(payload: str) -> bool:
    pl = payload.lower()
    return any(scheme in pl for scheme in _DANGEROUS_SCHEMES)
