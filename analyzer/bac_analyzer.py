from __future__ import annotations


def validate_bac(test_result: dict) -> tuple[bool, str]:
    """Broken Access Control 검증 — executor 플랫 출력 포맷 기준"""
    url    = (test_result.get("url") or "").lower()
    status = test_result.get("status") or 0
    body   = (test_result.get("response_body") or "").lower()
    role   = ((test_result.get("meta") or {}).get("role") or "guest")

    admin_paths = ["/adm/", "/wp-admin", "/install/"]
    is_admin_path = any(path in url for path in admin_paths)

    if is_admin_path and role != "admin":
        if status == 200:
            login_indicators = ["login", "로그인", "auth", "접근 권한"]
            if not any(ind in body for ind in login_indicators):
                admin_indicators = ["admin", "관리자", "회원관리", "설정", "dashboard"]
                if any(ind in body for ind in admin_indicators):
                    return True, f"BAC 성공 (비인가 계정 '{role}'으로 관리자 기능 접근)"

    return False, "안전함 (권한 통제 정상)"