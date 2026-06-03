"""
bac/runner.py — BAC 테스트 실행 단계

crawl 단계가 만들어 둔 재료를 사용해 analyzer가 먹을 수 있는 결과를 생성한다.
  입력: crawl_result.json (발견된 URL 목록), auth_cookies_<role>.json (역할별 세션)
  처리: 각 URL을 역할별 쿠키로 GET 재요청 → 본문 포함 응답 수집
  출력: execution_results 형식 dict 리스트 (meta.vuln_type="bac", meta.role 태깅)

analyzer.validate / detect_bac_group 이 이 결과를 그대로 판정한다.
페이로드 주입이 아니라 '같은 URL을 역할만 바꿔 요청'하는 구조라
probe.executor 대신 자체 GET 루프를 쓴다.
"""

from __future__ import annotations

import json
import os
import time
from typing import Optional

import requests

# 역할 우선순위 — 낮은 권한이 높은 권한 페이지에 접근되면 의심
_ROLE_ORDER = ["guest", "member", "user", "manager", "admin"]

_DEFAULT_TIMEOUT = 10
_DEFAULT_DELAY = 0.0


def _load_json(path: str):
    if not os.path.exists(path):
        return None
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def _discover_role_cookies(run_path_fn) -> dict[str, dict]:
    """auth_cookies_<role>.json 파일들을 모아 role -> cookies 매핑 생성."""
    role_cookies: dict[str, dict] = {}
    for role in _ROLE_ORDER:
        cookies = _load_json(run_path_fn(f"auth_cookies_{role}.json"))
        if isinstance(cookies, dict):
            role_cookies[role] = cookies
    # guest는 쿠키가 없을 수 있으므로 항상 포함 (비인증 요청)
    role_cookies.setdefault("guest", {})
    return role_cookies


def _collect_urls(crawl_pages) -> list[str]:
    """crawl_result.json에서 GET 재요청할 URL 목록 추출 (중복 제거)."""
    urls: list[str] = []
    seen: set[str] = set()
    if not isinstance(crawl_pages, list):
        return urls
    for page in crawl_pages:
        if not isinstance(page, dict):
            continue
        url = page.get("url")
        if url and url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def _make_session() -> requests.Session:
    s = requests.Session()
    s.headers.update({
        "User-Agent": "Mozilla/5.0 (compatible; LADS-BAC/1.0)",
    })
    return s


def build_bac_results(
    run_path_fn,
    timeout: int = _DEFAULT_TIMEOUT,
    delay: float = _DEFAULT_DELAY,
    progress_callback=None,
) -> list[dict]:
    """
    crawl 결과 URL × 역할별 쿠키로 GET 재요청 → analyzer 입력 형식 결과 리스트.

    반환 항목 스키마 (execution_results.json 호환):
      {
        "id": "bac_000123_member",
        "url": "...", "method": "GET", "inject_param": None,
        "status": 200, "response_body": "...", "length": 1234, "elapsed": 0.12,
        "error": None,
        "meta": {"vuln_type": "bac", "role": "member"},
      }
    """
    crawl_pages = _load_json(run_path_fn("crawl_result.json"))
    urls = _collect_urls(crawl_pages)
    role_cookies = _discover_role_cookies(run_path_fn)

    if not urls or not role_cookies:
        print(f"[BAC] 입력 부족 — urls={len(urls)}, roles={list(role_cookies)}")
        return []

    print(f"[BAC] 재요청 대상: URL {len(urls)}개 × 역할 {list(role_cookies)}")

    session = _make_session()
    results: list[dict] = []
    total = len(urls) * len(role_cookies)
    done = 0
    tid = 0

    for url in urls:
        for role, cookies in role_cookies.items():
            if delay:
                time.sleep(delay)

            base = {
                "id": f"bac_{tid:06d}_{role}",
                "point": "bac",
                "url": url,
                "method": "GET",
                "inject_param": None,
                "payload": None,
                "inject_mode": None,
                "meta": {"vuln_type": "bac", "role": role},
                "error": None,
            }
            tid += 1

            try:
                started = time.perf_counter()
                resp = session.get(
                    url,
                    cookies=cookies or {},
                    timeout=timeout,
                    allow_redirects=False,  # 302 리다이렉트를 200으로 둔갑시키지 않음
                )
                elapsed = time.perf_counter() - started
                body = resp.text or ""
                results.append({
                    **base,
                    "status": resp.status_code,
                    "response_body": body,
                    "length": len(body),
                    "elapsed": elapsed,
                })
            except requests.RequestException as exc:
                results.append({**base, "error": str(exc)[:120]})

            done += 1
            if progress_callback:
                progress_callback(done, total)

    ok = sum(1 for r in results if not r.get("error"))
    print(f"[BAC] 재요청 완료: 성공 {ok}/{len(results)}")
    return results