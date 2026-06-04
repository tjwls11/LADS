from __future__ import annotations
from typing import Optional

from .xss_context import (
    is_in_safe_context, is_idx_in_safe_context,
    classify_context, context_has_dangerous_scheme,
    CTX_SAFE_TAG, CTX_COMMENT, CTX_URL_ATTR, CTX_EVENT_ATTR,
    CTX_SCRIPT, CTX_HTML_TEXT, CTX_ATTR, CTX_UNKNOWN,
)

# finding type 상수 — findings.py에 A 담당자가 추가 예정
XSS_SUSPICIOUS       = "XSS_SUSPICIOUS"
XSS_REFLECTED        = "XSS_REFLECTED"
XSS_STORED_REFLECTED = "XSS_STORED_REFLECTED"
XSS_VERIFIED         = "XSS_VERIFIED"  # Playwright 확인 시에만 사용, 현재 미구현

XSS_MARKERS = (
    "onerror=alert",
    "onload=alert",
    "onerror=eval",
    "ontoggle=alert",
    "onmouseover=alert",
    "onfocus=alert",
    "onstart=alert",
    "onanimationstart=alert",
    "src=x onerror",
    "<script>alert",
    "javascript:alert",
    "href=javascript:",
    "<svg/onload",
    "<svg onload",
    "<details open ontoggle",
    "onerror=prompt",
    "onerror=alert`",
    "onmouseover=alert`",
)

_ENCODED_TOKENS = ("&lt;", "&gt;", "&quot;", "&#x3c;", "&#60;", "&#x3e;", "&#62;")
_INERT_CONTEXTS  = {CTX_SAFE_TAG, CTX_COMMENT}
# CTX_SCRIPT 제외 — script 안 반사는 quote 탈출 없이 실행 불가, AST 없이 확정 불가
_DANGER_CONTEXTS = {CTX_HTML_TEXT, CTX_ATTR, CTX_EVENT_ATTR}


def _extract_body(test_result: dict) -> str:
    if "response" in test_result and isinstance(test_result["response"], dict):
        return test_result["response"].get("body") or ""
    return test_result.get("response_body") or ""


def _is_encoded(body: str, idx: int, marker_len: int, window: int = 30) -> bool:
    surrounding = body[max(0, idx - window): idx + marker_len + window]
    return any(tok in surrounding for tok in _ENCODED_TOKENS)


def _find_marker(body_lower: str, body_raw: str) -> tuple[Optional[str], str, int, Optional[str]]:
    # 모든 출현 확인. _DANGER_CONTEXTS 즉시 반환, 나머지는 fallback으로 보관.
    fallback: tuple[str, str, int, str] | None = None
    for marker in XSS_MARKERS:
        search = 0
        while True:
            idx = body_lower.find(marker, search)
            if idx == -1:
                break
            if _is_encoded(body_raw, idx, len(marker)):
                search = idx + 1
                continue
            ctx = classify_context(body_raw, idx)
            ev  = f"위험 마커 노출 ('{marker}')"
            if ctx in _DANGER_CONTEXTS:
                return ev, ctx, idx, marker
            if ctx == CTX_URL_ATTR and context_has_dangerous_scheme(marker):
                return ev, ctx, idx, marker
            if fallback is None:
                fallback = (ev, ctx, idx, marker)
            search = idx + 1
    if fallback:
        return fallback
    return None, CTX_UNKNOWN, -1, None


def _find_payload_reflection(payload: str, body_lower: str, body_raw: str) -> tuple[Optional[str], str, int]:
    if not payload:
        return None, CTX_UNKNOWN, -1
    pl = payload.lower().strip()
    if len(pl) < 6:
        return None, CTX_UNKNOWN, -1
    idx = body_lower.find(pl)
    if idx == -1:
        return None, CTX_UNKNOWN, -1
    return "페이로드 원문 반사", classify_context(body_raw, idx), idx


def _verdict(ctx: str, payload: str) -> tuple[str, str]:
    if ctx in _INERT_CONTEXTS:
        return XSS_SUSPICIOUS, "low"
    if ctx == CTX_URL_ATTR:
        if context_has_dangerous_scheme(payload):
            return XSS_REFLECTED, "medium"
        return XSS_SUSPICIOUS, "low"
    if ctx in _DANGER_CONTEXTS:
        return XSS_REFLECTED, "medium"
    return XSS_SUSPICIOUS, "low"


# returns (found, evidence, xss_type, confidence). __init__.py _validate_single()이 4-tuple을 받도록 A 담당자가 수정 필요.
def validate_xss(test_result: dict) -> tuple[bool, str, str, str]:
    _NO = (False, "안전함 (XSS 시그니처 미검출 / 인코딩됨)", XSS_SUSPICIOUS, "low")

    if not test_result:
        return False, "검증 불가 (입력 없음)", XSS_SUSPICIOUS, "low"

    try:
        status = int(test_result.get("status") or 0)
    except (TypeError, ValueError):
        status = 0
    if status >= 300:
        return _NO

    body_raw = _extract_body(test_result)
    if not body_raw:
        return False, "검증 불가 (응답 본문 없음)", XSS_SUSPICIOUS, "low"

    body_lower = body_raw.lower()
    payload    = test_result.get("payload") or ""

    ev, ctx, idx, found_marker = _find_marker(body_lower, body_raw)
    if ev and found_marker is not None:
        if is_idx_in_safe_context(body_raw, idx):
            return True, f"[{ctx}] {ev} — safe context 억제", XSS_SUSPICIOUS, "low"
        xss_type, confidence = _verdict(ctx, found_marker)
        return True, f"[{ctx}] {ev}", xss_type, confidence

    ev, ctx, idx = _find_payload_reflection(payload, body_lower, body_raw)
    if ev:
        if is_idx_in_safe_context(body_raw, idx):
            return True, f"[{ctx}] {ev} — safe context 억제", XSS_SUSPICIOUS, "low"
        return True, f"[{ctx}] {ev}", XSS_SUSPICIOUS, "low"

    verify_raw = test_result.get("verify_body") or ""
    if verify_raw:
        verify_lower = verify_raw.lower()
        ev, ctx, idx, found_marker = _find_marker(verify_lower, verify_raw)
        if ev and found_marker is not None:
            if is_idx_in_safe_context(verify_raw, idx):
                return True, f"Stored [{ctx}] {ev} — safe context 억제", XSS_SUSPICIOUS, "low"
            _, confidence = _verdict(ctx, found_marker)
            return True, f"Stored [{ctx}] {ev}", XSS_STORED_REFLECTED, confidence
        ev, ctx, idx = _find_payload_reflection(payload, verify_lower, verify_raw)
        if ev:
            if is_idx_in_safe_context(verify_raw, idx):
                return True, f"Stored [{ctx}] {ev} — safe context 억제", XSS_SUSPICIOUS, "low"
            return True, f"Stored [{ctx}] {ev}", XSS_STORED_REFLECTED, "medium"

    return _NO
