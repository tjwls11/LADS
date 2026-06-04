from __future__ import annotations

import json
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


_HIDDEN_TAG_RE = re.compile(r"<input[^>]+>", re.IGNORECASE | re.DOTALL)
_INPUT_TYPE_RE = re.compile(r'\btype=["\']([^"\']+)["\']', re.IGNORECASE)
_INPUT_NAME_RE = re.compile(r'\bname=["\']([^"\']+)["\']', re.IGNORECASE)
_INPUT_VALUE_RE = re.compile(r'\bvalue=["\']([^"\']*)["\']', re.IGNORECASE)
_CSRF_NAME_RE = re.compile(r"(csrf|token|nonce|_token|authenticity|captcha)", re.IGNORECASE)

# 스레드별 독립 세션 저장소
_local = threading.local()


def _fetch_fresh_csrf(session: requests.Session, source_url: str, timeout: int) -> dict[str, str]:
    """GET source_url, extract fresh values for any CSRF hidden inputs."""
    try:
        r = session.get(source_url, timeout=timeout, allow_redirects=True)
        tokens: dict[str, str] = {}
        for tag in _HIDDEN_TAG_RE.findall(r.text):
            m_type = _INPUT_TYPE_RE.search(tag)
            if not (m_type and m_type.group(1).lower() == "hidden"):
                continue
            m_name = _INPUT_NAME_RE.search(tag)
            if not m_name:
                continue
            field_name = m_name.group(1)
            if not _CSRF_NAME_RE.search(field_name):
                continue
            m_val = _INPUT_VALUE_RE.search(tag)
            tokens[field_name] = m_val.group(1) if m_val else ""
        return tokens
    except Exception:
        return {}


def _make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) "
                "Chrome/120.0.0.0 Safari/537.36"
            ),
            "Accept": "*/*",
        }
    )
    # status_forcelist 제거: 서버 5xx는 SQLi 결과일 수 있어 재시도 금지
    # connect 재시도만 최소한으로 허용 (네트워크 순단 대응)
    retry = Retry(
        total=1,
        connect=1,
        read=0,
        status=0,
        backoff_factor=0,
    )
    s.mount("http://", HTTPAdapter(max_retries=retry))
    s.mount("https://", HTTPAdapter(max_retries=retry))
    return s


def _get_session() -> requests.Session:
    """스레드별 독립 세션 반환 — 없으면 새로 생성."""
    if not hasattr(_local, "session"):
        _local.session = _make_session()
    return _local.session


def _execute_single(t: dict, session: requests.Session, timeout: int, delay: float) -> dict:
    """태스크 하나 실행 → 결과 dict 반환."""
    if delay:
        time.sleep(delay)

    point = t.get("point")
    payload = t.get("payload")
    inject_mode = t.get("inject_mode", "replace")
    inject_location = t.get("inject_location", "query")
    inject_param = t.get("inject_param")

    base: dict[str, Any] = {
        "id": t.get("id"),
        "point": point,
        "task_group_id": t.get("task_group_id"),
        "payload": payload,
        "inject_mode": inject_mode,
        "inject_location": inject_location,
        "inject_param": inject_param,
        "base_value": t.get("base_value"),
        "meta": t.get("meta") or {},
        "error": None,
    }

    url = t.get("url")
    method = str(t.get("method", "GET")).upper()

    if not url:
        return {**base, "error": "invalid_task"}

    base_params = dict(t.get("base_params") or {})
    base_headers = dict(t.get("base_headers") or {})
    base_cookies = dict(t.get("base_cookies") or {})

    # noop: payload 주입 없이 원본 요청만 전송 (baseline/safe 요청용)
    if inject_mode == "noop":
        started = time.perf_counter()
        try:
            resp = session.get(
                url,
                params=base_params or None,
                headers=base_headers,
                cookies=base_cookies,
                timeout=timeout,
                allow_redirects=True,
            )
            elapsed = time.perf_counter() - started
            try:
                body_text = resp.text
            except Exception:
                body_text = None
            return {
                **base,
                "url": url,
                "method": "GET",
                "status": resp.status_code,
                "length": len(resp.content) if resp.content is not None else None,
                "elapsed": round(elapsed, 3),
                "response_body": body_text[:20000] if body_text else None,
            }
        except requests.Timeout:
            elapsed = time.perf_counter() - started
            return {**base, "url": url, "method": "GET", "status": None, "length": 0,
                    "elapsed": round(elapsed, 3), "response_body": None, "error": "timeout"}
        except Exception as e:
            elapsed = time.perf_counter() - started
            return {**base, "url": url, "method": "GET", "status": None, "length": 0,
                    "elapsed": round(elapsed, 3), "response_body": None, "error": f"exception:{type(e).__name__}"}

    if payload is None or not inject_param:
        return {**base, "error": "invalid_task"}

    base_params = dict(t.get("base_params") or {})
    base_headers = dict(t.get("base_headers") or {})
    base_cookies = dict(t.get("base_cookies") or {})
    base_value   = str(t.get("base_value") or "")

    if t.get("needs_csrf_refresh") and method == "POST":
        src = t.get("source_url", "")
        if src:
            base_params.update(_fetch_fresh_csrf(session, src, timeout))

    if inject_mode == "append":
        injected = f"{base_value}{payload}"
    else:
        injected = str(payload)

    params = None
    data = None
    headers = dict(base_headers)
    cookies = dict(base_cookies)

    loc = str(inject_location).lower()
    if loc == "header":
        headers[str(inject_param)] = injected
        if method == "POST":
            data = dict(base_params)
        else:
            params = dict(base_params)
    elif loc == "cookie":
        cookies[str(inject_param)] = injected
        if method == "POST":
            data = dict(base_params)
        else:
            params = dict(base_params)
    elif loc == "body":
        data = dict(base_params)
        data[str(inject_param)] = injected
    else:
        params = dict(base_params)
        params[str(inject_param)] = injected

    started = time.perf_counter()
    try:
        if method == "POST":
            enctype = str(t.get("enctype") or "").lower()
            if "multipart" in enctype and data:
                resp = session.post(
                    url,
                    params=params,
                    files={k: (None, str(v)) for k, v in data.items()},
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    allow_redirects=True,
                )
            else:
                resp = session.post(
                    url,
                    params=params,
                    data=data,
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    allow_redirects=True,
                )
        else:
            resp = session.get(
                url,
                params=params,
                headers=headers,
                cookies=cookies,
                timeout=timeout,
                allow_redirects=True,
            )

        elapsed = time.perf_counter() - started
        try:
            body_text = resp.text
        except Exception:
            body_text = None

        # Stored XSS 검증: POST 성공 후 source_url GET → 렌더링 페이지 확인
        verify_body = None
        source_url = t.get("source_url", "")
        is_xss_post = (
            method == "POST"
            and source_url
            and "xss" in str(t.get("meta", {}).get("vuln_type", "")).lower()
            and resp.status_code is not None
            and resp.status_code < 500
        )
        if is_xss_post:
            try:
                vresp = session.get(
                    source_url,
                    headers=headers,
                    cookies=cookies,
                    timeout=timeout,
                    allow_redirects=True,
                )
                verify_body = vresp.text[:20000] if vresp.text else None
            except Exception:
                verify_body = None

        return {
            **base,
            "url": url,
            "method": method,
            "status": resp.status_code,
            "length": len(resp.content) if resp.content is not None else None,
            "elapsed": round(elapsed, 3),
            "response_body": body_text[:20000] if body_text else None,
            "verify_body": verify_body,
        }
    except requests.Timeout:
        elapsed = time.perf_counter() - started
        return {
            **base,
            "url": url,
            "method": method,
            "status": None,
            "length": 0,
            "elapsed": round(elapsed, 3),
            "response_body": None,
            "error": "timeout",
        }
    except Exception as e:
        elapsed = time.perf_counter() - started
        return {
            **base,
            "url": url,
            "method": method,
            "status": None,
            "length": 0,
            "elapsed": round(elapsed, 3),
            "response_body": None,
            "error": f"exception:{type(e).__name__}",
        }


def execute(
    tasks: list[dict],
    timeout: int = 10,
    delay: float = 0.0,
    output_file: str | None = None,
    progress_callback=None,
    workers: int = 10,
) -> list[dict]:
    # probe task -> HTTP 병렬 전송 -> results

    total = len(tasks)

    results: list[dict | None] = [None] * total
    _lock = threading.Lock()
    _done = [0]

    def _run(idx: int, t: dict) -> None:
        session = _get_session()
        result = _execute_single(t, session, timeout, delay)
        results[idx] = result
        if progress_callback and total > 0:
            with _lock:
                _done[0] += 1
                progress_callback(_done[0], total)

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(_run, i, t) for i, t in enumerate(tasks)]
        for f in as_completed(futures):
            try:
                f.result()
            except Exception:
                pass  # 개별 태스크 오류는 result dict의 error 필드에 기록됨

    final_results = [r for r in results if r is not None]

    if output_file:
        parent = os.path.dirname(output_file)
        if parent:
            os.makedirs(parent, exist_ok=True)

        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(final_results, f, ensure_ascii=False, indent=2)

    return final_results
