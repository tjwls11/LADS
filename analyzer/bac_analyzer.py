from __future__ import annotations

import re
from collections import defaultdict
from difflib import SequenceMatcher

from findings import VERDICT_CONFIRMED, VERDICT_SUSPECTED, VERDICT_CANDIDATE

# ── 임계치 ───────────────────────────────────────────────────────
MIN_VULN_BODY_SIZE     = 500
ADMIN_SIMILARITY_THRES = 0.85
SUSPICIOUS_RATIO       = 0.5

# difflib 유사도 계산 비용 제어용 — 본문을 앞에서 이만큼만 잘라 비교
_SIMILARITY_SAMPLE_LEN = 4000

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


def is_login_page(body: str) -> bool:
    if not body:
        return False
    if any(p.search(body) for p in _LOGIN_FORM_PATTERNS):
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


def _has_idor_meta(r: dict) -> bool:
    meta_idor = (r.get("meta") or {}).get("idor")
    if isinstance(meta_idor, dict) and meta_idor.get("param"):
        return True
    return bool(r.get("idor_param"))


# ── 응답 유사도 ───────────────────────────────────────────────────
def body_similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    if a == b:
        return 1.0
    sa = a[:_SIMILARITY_SAMPLE_LEN]
    sb = b[:_SIMILARITY_SAMPLE_LEN]
    return SequenceMatcher(None, sa, sb).ratio()


# ── 단건 판정 ─────────────────────────────────────────────────────
# 반환: (취약여부, evidence, verdict)
def validate_bac(test_result: dict) -> tuple[bool, str, str]:
    if not test_result:
        return False, "검증 불가 (입력 없음)", VERDICT_CANDIDATE

    # IDOR 메타가 달린 결과는 단건에서 판정하지 않고 detect_idor_group 에 위임.
    # (소유권 비교는 그룹 detector 의 책임)
    if _has_idor_meta(test_result):
        return False, "IDOR 그룹 분석 대상 (Phase 2로 위임)", VERDICT_CANDIDATE

    url  = (test_result.get("url") or "").lower()
    resp = _extract(test_result)
    role = _get_role(test_result)

    status = resp["status"]
    body   = resp["body"]
    size   = resp["size"]

    # 1단계: Forced Browsing — 민감 경로 직접 노출
    if is_sensitive_path(url):
        if status == 200 and size >= MIN_VULN_BODY_SIZE:
            if not is_error_page(body, status):
                return (
                    True,
                    f"[VULNERABLE] forced_browsing — 민감 경로 '{url}' 노출 (size={size})",
                    VERDICT_CONFIRMED,
                )

    # 2단계: 수직적 권한 상승
    if role == "admin":
        return False, "안전함 (admin baseline)", VERDICT_CANDIDATE
    if status != 200:
        return False, f"안전함 (status={status}, 차단됨)", VERDICT_CANDIDATE
    if is_login_page(body):
        return False, "안전함 (로그인 페이지로 리다이렉트됨)", VERDICT_CANDIDATE
    if is_error_page(body, status):
        return False, "안전함 (권한 거부 페이지)", VERDICT_CANDIDATE
    if size < MIN_VULN_BODY_SIZE:
        return False, f"안전함 (빈 응답 size={size})", VERDICT_CANDIDATE

    if role in ("guest", "member", "user"):
        return (
            True,
            f"[VULNERABLE] vertical_escalation — '{role}' 권한으로 '{url}' 접근 성공 (size={size})",
            VERDICT_SUSPECTED,
        )

    return False, "안전함 (role 정보 없음, 그룹 분석 대기)", VERDICT_CANDIDATE


# ── 그룹 단위 BAC 분석 ────────────────────────────────────────────
def detect_bac_group(results: list[dict]) -> list[dict]:
    bac_results = [
        r for r in results
        if not r.get("error")
        and r.get("response_body")
        and ("bac" in _vuln_type(r) or "broken_access" in _vuln_type(r))
        and not _has_idor_meta(r)
    ]
    if not bac_results:
        return []

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in bac_results:
        key = (r.get("url"), r.get("method") or "GET")
        groups[key].append(r)

    detected: list[dict] = []

    for (url, _method), group in groups.items():
        by_role: dict[str, dict] = {}
        for r in group:
            by_role[_get_role(r)] = r

        admin      = by_role.get("admin")
        member     = by_role.get("member") or by_role.get("user")
        guest      = by_role.get("guest") or by_role.get("unknown")
        admin_data = _extract(admin) if admin else None

        for low_role_name, low_resp in [("member", member), ("guest", guest)]:
            if not low_resp:
                continue

            data = _extract(low_resp)
            if data["status"] != 200:
                continue
            if is_login_page(data["body"]) or is_error_page(data["body"], data["status"]):
                continue
            if data["size"] < MIN_VULN_BODY_SIZE:
                continue

            if admin_data and admin_data["status"] == 200:
                sim = body_similarity(data["body"], admin_data["body"])
                if sim >= ADMIN_SIMILARITY_THRES:
                    evidence = (
                        f"BAC vertical_escalation: '{low_role_name}'이 admin과 유사 "
                        f"(유사도 {sim:.0%}, size={data['size']} vs admin={admin_data['size']})"
                    )
                    detected.append({"result": low_resp, "evidence": evidence, "verdict": VERDICT_CONFIRMED})
                elif sim >= SUSPICIOUS_RATIO:
                    evidence = (
                        f"BAC suspected: '{low_role_name}'이 admin과 부분 유사 "
                        f"(유사도 {sim:.0%}, 수동 확인 필요)"
                    )
                    detected.append({"result": low_resp, "evidence": evidence, "verdict": VERDICT_SUSPECTED})
            else:
                evidence = (
                    f"BAC vertical_escalation: '{low_role_name}' 권한으로 '{url}' 접근 성공 "
                    f"(status=200, size={data['size']}, 로그인 페이지 아님)"
                )
                detected.append({"result": low_resp, "evidence": evidence, "verdict": VERDICT_SUSPECTED})

    return detected


def detect_idor_group(results: list[dict]) -> list[dict]:
    idor_results = []
    for r in results:
        if r.get("error") or not r.get("response_body"):
            continue
        meta_idor = (r.get("meta") or {}).get("idor")
        param = None
        object_id = None
        owner = None
        if isinstance(meta_idor, dict):
            param = meta_idor.get("param")
            object_id = meta_idor.get("object_id")
            owner = meta_idor.get("owner")
        else:
            param = r.get("idor_param")
            object_id = r.get("idor_object_id")
            owner = r.get("idor_owner")
        if not param:
            continue
        idor_results.append({
            "r": r,
            "param": param,
            "object_id": object_id,
            "owner": (owner or "").lower(),
        })

    if not idor_results:
        return []

    detected: list[dict] = []

    for item in idor_results:
        r = item["r"]
        data = _extract(r)
        if data["status"] != 200:
            continue
        if is_login_page(data["body"]) or is_error_page(data["body"], data["status"]):
            continue
        if data["size"] < MIN_VULN_BODY_SIZE:
            continue

        param = item["param"]
        object_id = item["object_id"]
        owner = item["owner"]
        role = _get_role(r)

        if owner and owner not in ("self", "own", role):
            evidence = (
                f"IDOR suspected: 타인 소유 객체 접근 성공 "
                f"(param={param}, id={object_id}, owner={owner}, role={role}, "
                f"status=200, size={data['size']}) — 소유권 검증 부재 의심"
            )
            verdict = VERDICT_SUSPECTED
        else:
            evidence = (
                f"IDOR candidate: 객체 ID 조작 접근 "
                f"(param={param}, id={object_id}, role={role}, status=200, "
                f"size={data['size']}) — 소유권 정보 부족, 수동 확인 필요"
            )
            verdict = VERDICT_CANDIDATE

        detected.append({"result": r, "evidence": evidence, "verdict": verdict})

    return detected