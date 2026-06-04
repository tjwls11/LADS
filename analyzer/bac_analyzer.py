from __future__ import annotations

import re
from collections import defaultdict

# ── 임계치 ───────────────────────────────────────────────────────
MIN_VULN_BODY_SIZE     = 500
ADMIN_SIMILARITY_THRES = 0.85
SUSPICIOUS_RATIO       = 0.5

# ── 로그인 페이지 식별 ─────────────────────────────────────────────
_LOGIN_FORM_PATTERNS = [
    re.compile(r'<input[^>]+type=["\']password["\']', re.IGNORECASE),
    re.compile(r'<input[^>]+name=["\'](?:mb_password|password|passwd|pwd)["\']', re.IGNORECASE),
    re.compile(r'name=["\']mb_id["\']', re.IGNORECASE),
    re.compile(r'<form[^>]+action=["\'][^"\']*login', re.IGNORECASE),
]

_LOGIN_TEXT_HINTS = [
    "로그인이 필요", "login required", "please log in",
    "세션이 만료", "재로그인",
]

_LOGIN_JS_REDIRECT_RE = re.compile(
    r"(?:document\.location|location\.replace|location\.href)\s*[=(]['\"]([^'\"]*login[^'\"]*)['\"]",
    re.IGNORECASE,
)

_LOGIN_JS_REDIRECT_RE = re.compile(
    r"(?:document\.location|location\.replace|location\.href)\s*[=(]['\"]([^'\"]*login[^'\"]*)['\"]",
    re.IGNORECASE,
)


def is_login_page(body: str) -> bool:
    if not body:
        return False
    if any(p.search(body) for p in _LOGIN_FORM_PATTERNS):
        return True
    if _LOGIN_JS_REDIRECT_RE.search(body):
        return True
    if _LOGIN_JS_REDIRECT_RE.search(body):
        return True
    body_lower = body.lower()
    return sum(1 for h in _LOGIN_TEXT_HINTS if h.lower() in body_lower) >= 2


# ── 에러/권한거부 페이지 식별 ─────────────────────────────────────
_ERROR_PATTERNS = [
    re.compile(r'권한이?\s*없', re.IGNORECASE),
    re.compile(r'access\s+denied', re.IGNORECASE),
    re.compile(r'forbidden', re.IGNORECASE),
    re.compile(r'unauthorized', re.IGNORECASE),
    re.compile(r'관리자만\s*(?:접근|이용)', re.IGNORECASE),
    re.compile(r'잘못된\s*접근', re.IGNORECASE),
    # Gnuboard JS alert 차단 패턴 (alert + window.close / history.back)
    # 내부 괄호 포함 매칭: alert("포인트(0)..."); history.back()
    re.compile(
        r'alert\s*\((?:[^)(]|\([^)]*\))*\)\s*;\s*(?:window\.close|history\.back)',
        re.IGNORECASE | re.DOTALL,
    ),
    # Gnuboard JS alert 차단 패턴 (alert + window.close / history.back)
    # 내부 괄호 포함 매칭: alert("포인트(0)..."); history.back()
    re.compile(
        r'alert\s*\((?:[^)(]|\([^)]*\))*\)\s*;\s*(?:window\.close|history\.back)',
        re.IGNORECASE | re.DOTALL,
    ),
]


def is_error_page(body: str, status: int) -> bool:
    if status in (401, 403, 404, 500, 503):
        return True
    if not body:
        return False
    return any(p.search(body) for p in _ERROR_PATTERNS)


# ── 민감 경로 식별 ────────────────────────────────────────────────
_SENSITIVE_PATH_PATTERNS = [
    re.compile(r'/install/?', re.IGNORECASE),
    re.compile(r'/setup/?', re.IGNORECASE),
    re.compile(r'/test\.php', re.IGNORECASE),
    re.compile(r'/debug\.php', re.IGNORECASE),
    re.compile(r'/phpinfo\.php', re.IGNORECASE),
    re.compile(r'/info\.php', re.IGNORECASE),
    re.compile(r'/\.git/', re.IGNORECASE),
    re.compile(r'/\.env', re.IGNORECASE),
    re.compile(r'/backup', re.IGNORECASE),
    re.compile(r'\.bak(\?|$)', re.IGNORECASE),
    re.compile(r'\.old(\?|$)', re.IGNORECASE),
    re.compile(r'\.sql(\?|$)', re.IGNORECASE),
]


def is_sensitive_path(url: str) -> bool:
    if not url:
        return False
    return any(p.search(url) for p in _SENSITIVE_PATH_PATTERNS)


# ── 응답 정규화 ───────────────────────────────────────────────────
def _extract(r: dict) -> dict:
    if "response" in r and isinstance(r["response"], dict):
        resp = r["response"]
        return {
            "status": resp.get("status") or 0,
            "body":   resp.get("body") or "",
            "size":   resp.get("length") or len(resp.get("body") or ""),
        }
    body = r.get("response_body") or ""
    return {
        "status": r.get("status") or 0,
        "body":   body,
        "size":   r.get("length") or len(body),
    }


def _get_role(r: dict) -> str:
    meta = r.get("meta") or {}
    role = meta.get("role")
    if role:
        return role.lower()
    req_info = r.get("request_info") or {}
    return (req_info.get("role") or "unknown").lower()


def _vuln_type(r: dict) -> str:
    return ((r.get("meta") or {}).get("vuln_type") or "").lower()


# ── 응답 유사도 ───────────────────────────────────────────────────
def body_similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    if hash(a) == hash(b):
    if hash(a) == hash(b):
        return 1.0
    la, lb = len(a), len(b)
    return min(la, lb) / max(la, lb)


# 로그인/권한거부가 아닌 정상 접근 응답인지 반환
def _is_success_content(data: dict) -> bool:
    return (
        data["status"] == 200
        and data["size"] >= MIN_VULN_BODY_SIZE
        and not is_login_page(data["body"])
        and not is_error_page(data["body"], data["status"])
    )


# 결과 메타데이터에서 시나리오 이름을 반환
def _get_scenario(r: dict) -> str:
    return ((r.get("meta") or {}).get("scenario") or "").lower()


# ── 단건 판정 ─────────────────────────────────────────────────────
def validate_bac(test_result: dict) -> tuple[bool, str]:
def validate_bac(test_result: dict) -> tuple[bool, str]:
    if not test_result:
        return False, "검증 불가 (입력 없음)"
        return False, "검증 불가 (입력 없음)"

    url  = (test_result.get("url") or "").lower()
    resp = _extract(test_result)
    role = _get_role(test_result)

    status = resp["status"]
    body   = resp["body"]
    size   = resp["size"]

    # 1단계: Forced Browsing
    # 1단계: Forced Browsing
    if is_sensitive_path(url):
        if status == 200 and size >= MIN_VULN_BODY_SIZE:
            if not is_login_page(body) and not is_error_page(body, status):
                return True, f"[VULNERABLE] forced_browsing — 민감 경로 '{url}' 노출 (size={size})"
            if not is_login_page(body) and not is_error_page(body, status):
                return True, f"[VULNERABLE] forced_browsing — 민감 경로 '{url}' 노출 (size={size})"

    # 2단계: 수직적 권한 상승
    if role == "admin":
        return False, "안전함 (admin baseline)"
        return False, "안전함 (admin baseline)"
    if status != 200:
        return False, f"안전함 (status={status}, 차단됨)"
        return False, f"안전함 (status={status}, 차단됨)"
    if is_login_page(body):
        return False, "안전함 (로그인 페이지로 리다이렉트됨)"
        return False, "안전함 (로그인 페이지로 리다이렉트됨)"
    if is_error_page(body, status):
        return False, "안전함 (권한 거부 페이지)"
        return False, "안전함 (권한 거부 페이지)"
    if size < MIN_VULN_BODY_SIZE:
        return False, f"안전함 (빈 응답 size={size})"
        return False, f"안전함 (빈 응답 size={size})"

    if role in ("guest", "member", "member1", "user"):
        return True, f"[VULNERABLE] vertical_escalation — '{role}' 권한으로 '{url}' 접근 성공 (size={size})"

    return False, "안전함 (role 정보 없음, 그룹 분석 대기)"
    return False, "안전함 (role 정보 없음, 그룹 분석 대기)"


# ── 그룹 단위 BAC 분석 ────────────────────────────────────────────
def detect_bac_group(results: list[dict]) -> list[dict]:
    bac_results = [
        r for r in results
        if not r.get("error")
        and r.get("response_body")
        and ("bac" in _vuln_type(r) or "broken_access" in _vuln_type(r))
    ]
    if not bac_results:
        return []

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in bac_results:
        meta = r.get("meta") or {}
        key = (
            meta.get("scenario_id") or r.get("point") or r.get("url"),
            r.get("url"),
            r.get("method") or "GET",
        )
        groups[key].append(r)

    detected: list[dict] = []

    for (_point, url, _method), group in groups.items():
        by_role: dict[str, dict] = {}
        for r in group:
            by_role[_get_role(r)] = r

        scenario = _get_scenario(group[0])
        admin      = by_role.get("admin")
        member1     = by_role.get("member1") or by_role.get("member") or by_role.get("user")
        guest      = by_role.get("guest") or by_role.get("unknown")
        admin_data = _extract(admin) if admin else None

        if scenario == "member_only_guest_access":
            if not member1 or not guest:
                continue

            member_data = _extract(member1)
            guest_data = _extract(guest)
            if not _is_success_content(member_data) or not _is_success_content(guest_data):
                continue

            sim = body_similarity(guest_data["body"], member_data["body"])
            if sim >= SUSPICIOUS_RATIO:
                evidence = (
                    f"BAC member_only_guest_access: 'guest'가 member 전용 URL '{url}'에 접근 성공 "
                    f"(member 유사도={sim:.0%}, size={guest_data['size']})"
                )
            else:
                evidence = (
                    f"BAC member_only_guest_access: 'guest'가 member 전용 URL '{url}'에 접근 성공 "
                    f"(status=200, size={guest_data['size']}, 로그인/권한거부 페이지 아님)"
                )
            detected.append({"result": guest, "evidence": evidence})
            continue

        for low_role_name, low_resp in [("member1", member1), ("guest", guest)]:
            if not low_resp:
                continue

            data = _extract(low_resp)
            if not _is_success_content(data):
                continue

            if admin_data and admin_data["status"] == 200:
                sim = body_similarity(data["body"], admin_data["body"])
                if sim >= ADMIN_SIMILARITY_THRES:
                    evidence = (
                        f"BAC vertical_escalation: '{low_role_name}'이 admin과 유사 "
                        f"(유사도 {sim:.0%}, size={data['size']} vs admin={admin_data['size']})"
                    )
                    detected.append({"result": low_resp, "evidence": evidence})
                    detected.append({"result": low_resp, "evidence": evidence})
                elif sim >= SUSPICIOUS_RATIO:
                    evidence = (
                        f"BAC suspected: '{low_role_name}'이 admin과 부분 유사 "
                        f"(유사도 {sim:.0%}, 수동 확인 필요)"
                    )
                    detected.append({"result": low_resp, "evidence": evidence})
                    detected.append({"result": low_resp, "evidence": evidence})
            else:
                evidence = (
                    f"BAC vertical_escalation: '{low_role_name}' 권한으로 '{url}' 접근 성공 "
                    f"(status=200, size={data['size']}, 로그인 페이지 아님)"
                )
                detected.append({"result": low_resp, "evidence": evidence})
                detected.append({"result": low_resp, "evidence": evidence})

    return detected


def detect_idor_group(_results: list[dict]) -> list[dict]:
    """IDOR 판정 - 추후 구현 예정."""
    return []
def detect_idor_group(_results: list[dict]) -> list[dict]:
    """IDOR 판정 - 추후 구현 예정."""
    return []
