from __future__ import annotations

from typing import Optional

from findings import VERDICT_CONFIRMED, VERDICT_CANDIDATE

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
    # 백틱 변형
    "onerror=alert`",
    "onmouseover=alert`",
)

# 인코딩 흔적 — 마커 주변에 보이면 안전한 것으로 간주
_ENCODED_TOKENS = ("&lt;", "&gt;", "&quot;", "&#x3c;", "&#60;", "&#x3e;", "&#62;")


# ── 입력 정규화 ──────────────────────────────────────────────────
def _extract_body(test_result: dict) -> str:
    if "response" in test_result and isinstance(test_result["response"], dict):
        return test_result["response"].get("body") or ""
    return test_result.get("response_body") or ""


def _extract_recheck_body(test_result: dict) -> Optional[str]:
    sr = test_result.get("stored_recheck")
    if isinstance(sr, dict) and sr.get("body"):
        return sr.get("body")
    rr = test_result.get("recheck_response")
    if isinstance(rr, dict) and rr.get("body"):
        return rr.get("body")
    body = test_result.get("stored_recheck_body")
    if body:
        return body
    return None


# ── 헬퍼 ─────────────────────────────────────────────────────────
def _is_encoded(body: str, idx: int, marker_len: int, window: int = 10) -> bool:
    start = max(0, idx - window)
    end   = idx + marker_len + window
    surrounding = body[start:end]
    return any(tok in surrounding for tok in _ENCODED_TOKENS)


def _check_markers(body_lower: str, body_raw: str) -> Optional[str]:
    for marker in XSS_MARKERS:
        idx = body_lower.find(marker)
        if idx == -1:
            continue
        if _is_encoded(body_raw, idx, len(marker)):
            continue
        return f"위험 마커 노출 ('{marker}')"
    return None


def _check_payload_reflection(payload: str, body_lower: str) -> Optional[str]:
    if not payload:
        return None
    pl = payload.lower().strip()
    if len(pl) < 4:                     # 너무 짧은 문자열은 우연 매치 가능
        return None
    if pl in body_lower:
        return f"페이로드 반사 (payload 본문 내 그대로 노출)"
    return None


def _scan(body_raw: str, payload: str) -> Optional[str]:
    """본문에서 위험 마커 / 페이로드 반사를 탐지. 근거 문자열 or None."""
    if not body_raw:
        return None
    body_lower = body_raw.lower()
    msg = _check_markers(body_lower, body_raw)
    if msg:
        return msg
    return _check_payload_reflection(payload, body_lower)


# ── 메인 진입점 ──────────────────────────────────────────────────
# 반환: (취약여부, evidence, verdict)
def validate_xss(test_result: dict) -> tuple[bool, str, str]:

    if not test_result:
        return False, "검증 불가 (입력 없음)", VERDICT_CANDIDATE

    payload = (test_result.get("payload") or "")
    context = test_result.get("xss_context") or "unknown"

    # 1) Stored 재조회 본문이 있으면 그쪽을 최우선으로 검증 (가장 강한 증거).
    recheck_body = _extract_recheck_body(test_result)
    if recheck_body is not None:
        msg = _scan(recheck_body, payload)
        if msg:
            return True, f"Stored XSS 확정 [{context}] 재조회 페이지에서 {msg}", VERDICT_CONFIRMED
        # 재조회했는데 안 터졌다면 저장 시점만으로 단정하지 않는다 (아래 일반 검증으로 진행).

    # 2) 일반(저장/반사 시점) 응답 검증
    body_raw = _extract_body(test_result)
    if not body_raw:
        # 본문은 없지만 재조회도 실패한 경우
        if recheck_body is not None:
            return False, "안전함 (재조회 페이지에 페이로드 미반영)", VERDICT_CANDIDATE
        return False, "검증 불가 (응답 본문 없음)", VERDICT_CANDIDATE

    msg = _scan(body_raw, payload)
    if msg:
        return True, f"XSS 성공 [{context}] {msg}", VERDICT_CONFIRMED

    return False, "안전함 (XSS 시그니처 미검출 / 인코딩됨)", VERDICT_CANDIDATE