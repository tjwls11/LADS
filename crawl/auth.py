import os
import sys
from typing import Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv

load_dotenv()

# 로그인 관련 환경 변수
LOGIN_URL = os.getenv("LOGIN_URL", "")
LOGIN_METHOD = os.getenv("LOGIN_METHOD", "POST").upper()
LOGIN_ID_FIELD = os.getenv("LOGIN_ID_FIELD", "")
LOGIN_PASSWORD_FIELD = os.getenv("LOGIN_PASSWORD_FIELD", "")
LOGIN_ID = os.getenv("LOGIN_ID", "")
LOGIN_PASSWORD = os.getenv("LOGIN_PASSWORD", "")
LOGIN_SUCCESS_INDICATOR = os.getenv("LOGIN_SUCCESS_INDICATOR", "")
LOGIN_SUCCESS_URL_KEYWORD = os.getenv("LOGIN_SUCCESS_URL_KEYWORD", "")
LOGIN_FAIL_INDICATOR = os.getenv("LOGIN_FAIL_INDICATOR", "")

# BAC 멀티 세션용 관리자 계정
ADMIN_ID = os.getenv("ADMIN_ID", "")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")

_TIMEOUT = int(os.getenv("CRAWL_TIMEOUT", "10"))


# CSRF 토큰 등 hidden input 값 추출
def extract_hidden_inputs(form_tag) -> dict:
    hidden = {}
    if not form_tag:
        return hidden
    for inp in form_tag.find_all("input", {"type": "hidden"}):
        name = inp.get("name")
        if name:
            hidden[name] = inp.get("value", "")
    return hidden


# name/id/placeholder/autocomplete 속성으로 아이디, 비밀번호 필드 추론
def infer_login_fields(form_tag, id_field: str = "", password_field: str = "") -> Optional[tuple[str, str]]:
    inputs = form_tag.find_all("input")

    # 비밀번호 필드 찾기 (type=password 또는 키워드 매칭)
    password_name = password_field if password_field and form_tag.find("input", {"name": password_field}) else ""
    if not password_name:
        for inp in inputs:
            name = inp.get("name", "")
            input_type = inp.get("type", "text").lower()
            haystack = " ".join([name, inp.get("id", ""), inp.get("placeholder", ""), inp.get("autocomplete", "")]).lower()
            if name and (input_type == "password" or "pass" in haystack or "passwd" in haystack or "pw" in haystack):
                password_name = name
                break

    # 아이디 필드 찾기 (점수 기반: 이메일/텍스트 타입 + 관련 키워드 우선)
    id_name = id_field if id_field and form_tag.find("input", {"name": id_field}) else ""
    if not id_name:
        candidates = []
        for idx, inp in enumerate(inputs):
            name = inp.get("name", "")
            input_type = inp.get("type", "text").lower()
            if not name or name == password_name or input_type in {"hidden", "password", "submit", "button", "checkbox", "radio"}:
                continue
            haystack = " ".join([name, inp.get("id", ""), inp.get("placeholder", ""), inp.get("autocomplete", "")]).lower()
            score = 2 if input_type in {"text", "email", "tel"} else 0
            if any(token in haystack for token in ["login", "user", "userid", "username", "email", "member", "mb_id", "id"]):
                score += 5
            candidates.append((score, -idx, name))
        if candidates:
            id_name = max(candidates)[2]

    if id_name and password_name:
        return id_name, password_name
    return None


# 페이지에서 로그인 폼 탐색 (env 지정 필드 -> 추론 순서로 시도)
def find_login_form(soup: BeautifulSoup, id_field: str = "", password_field: str = ""):
    forms = soup.find_all("form")
    if id_field and password_field:
        for form in forms:
            if form.find("input", {"name": id_field}) and form.find("input", {"name": password_field}):
                return form
    for form in forms:
        if infer_login_fields(form, id_field, password_field):
            return form
    return forms[0] if forms else None


def login(
    session: requests.Session,
    url: str = LOGIN_URL,
    method: str = LOGIN_METHOD,
    id_field: str = LOGIN_ID_FIELD,
    password_field: str = LOGIN_PASSWORD_FIELD,
    login_id: str = LOGIN_ID,
    login_password: str = LOGIN_PASSWORD,
    success_indicator: str = LOGIN_SUCCESS_INDICATOR,
    success_url_keyword: str = LOGIN_SUCCESS_URL_KEYWORD,
    fail_indicator: str = LOGIN_FAIL_INDICATOR,
    timeout: int = _TIMEOUT,
) -> tuple[bool, dict]:

    # 로그인 수행, (성공 여부, 쿠키) 반환 — 실패 시 (False, {})
    if not url:
        return False, {}

    success_indicator = success_indicator.lower()
    success_url_keyword = success_url_keyword.lower()
    fail_indicator = fail_indicator.lower()

    try:
        get_resp = session.get(url, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        print(f"[LOGIN] GET failed: {exc}", file=sys.stderr)
        return False, {}

    soup = BeautifulSoup(get_resp.text, "lxml")
    form_tag = find_login_form(soup, id_field, password_field)
    if not form_tag:
        print("[LOGIN] login form not found", file=sys.stderr)
        return False, {}

    inferred = infer_login_fields(form_tag, id_field, password_field)
    if not inferred:
        print("[LOGIN] could not infer login fields", file=sys.stderr)
        return False, {}
    id_field, password_field = inferred

    # hidden 필드 포함해 페이로드 구성
    payload = extract_hidden_inputs(form_tag)
    payload[id_field] = login_id
    payload[password_field] = login_password
    post_url = urljoin(url, form_tag.get("action")) if form_tag.get("action") else url

    try:
        if method == "GET":
            post_resp = session.get(post_url, params=payload, timeout=timeout, allow_redirects=True)
        else:
            post_resp = session.post(post_url, data=payload, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        print(f"[LOGIN] request failed: {exc}", file=sys.stderr)
        return False, {}

    # 성공/실패 판단
    # 최종 URL -> 쿠키 존재 -> 실패 키워드(fallback) 순서로 확인
    body_lower = post_resp.text.lower()
    final_url_lower = post_resp.url.lower()
    cookies = session.cookies.get_dict()

    if success_url_keyword and success_url_keyword in final_url_lower:
        print(f"[LOGIN] success by final URL, cookies={len(cookies)}")
        return True, cookies
    if cookies:
        print(f"[LOGIN] success by cookies, cookies={len(cookies)}")
        return True, cookies
    if fail_indicator and fail_indicator in body_lower:
        print("[LOGIN] failed by fail indicator", file=sys.stderr)
        return False, {}

    print("[LOGIN] no success evidence found", file=sys.stderr)
    return False, {}


def _make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "ko-KR,ko;q=0.9,en;q=0.8",
    })
    return s


# 역할별 세션 쿠키 반환
def login_all_roles(
    url: str = LOGIN_URL,
    method: str = LOGIN_METHOD,
    id_field: str = LOGIN_ID_FIELD,
    password_field: str = LOGIN_PASSWORD_FIELD,
    success_indicator: str = LOGIN_SUCCESS_INDICATOR,
    success_url_keyword: str = LOGIN_SUCCESS_URL_KEYWORD,
    fail_indicator: str = LOGIN_FAIL_INDICATOR,
    timeout: int = _TIMEOUT,
) -> dict[str, dict]:

    # os.getenv 재호출
    _login_id       = os.getenv("LOGIN_ID", LOGIN_ID)
    _login_password = os.getenv("LOGIN_PASSWORD", LOGIN_PASSWORD)
    _admin_id       = os.getenv("ADMIN_ID", ADMIN_ID)
    _admin_password = os.getenv("ADMIN_PASSWORD", ADMIN_PASSWORD)

    roles: dict[str, dict] = {"guest": {}}

    common = dict(
        url=url, method=method, id_field=id_field, password_field=password_field,
        success_indicator=success_indicator, success_url_keyword=success_url_keyword,
        fail_indicator=fail_indicator, timeout=timeout,
    )

    if _login_id:
        s = _make_session()
        ok, cookies = login(s, login_id=_login_id, login_password=_login_password, **common)
        if ok:
            roles["member"] = cookies
            print(f"[AUTH] member session acquired: {len(cookies)} cookies")
        else:
            print("[AUTH] member login failed — member session skipped", file=sys.stderr)

    if _admin_id:
        s = _make_session()
        ok, cookies = login(s, login_id=_admin_id, login_password=_admin_password, **common)
        if ok:
            roles["admin"] = cookies
            print(f"[AUTH] admin session acquired: {len(cookies)} cookies")
        else:
            print("[AUTH] admin login failed — admin session skipped", file=sys.stderr)

    return roles
