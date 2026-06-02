from __future__ import annotations

import argparse
import json
import os
import re
from typing import Callable
from urllib.parse import urlparse
from utilities import _load_json
from crawl.auth import load_cookies
from probe.executor import execute


ROLE_ORDER = ("guest", "member1", "admin")
TASKS_FILE = "bac_vertical_tasks.json"
RESULTS_FILE = "bac_vertical_results.json"

# 관리자 URL 패턴
ADMIN_PATH_RE = re.compile(
    r"/(?:adm|admin|administrator|admincp|wp-admin|manager|manage|management|"
    r"backend|backoffice|console|control-panel|controlpanel|cpanel|dashboard|staff)(?:/|$)",
    re.IGNORECASE,
)

# 상태 변환을 시킬 수 있는 위험한 URL 패턴
DESTRUCTIVE_PATH_RE = re.compile(
    r"(delete|del_|remove|update|insert|write_update|save|logout|upload|drop)",
    re.IGNORECASE,
)


# 실행 경로 생성 함수가 없을 때 run_dir 기준 경로를 반환
def make_run_path_fn(run_dir: str) -> Callable[[str], str]:
    return lambda filename: os.path.join(run_dir, filename)


# 수직 권한 상승 테스트에서 위험한 URL인지 확인
def _is_safe_get_candidate(url: str) -> bool:
    path = urlparse(url).path.lower()
    return not DESTRUCTIVE_PATH_RE.search(path)


# 크롤 결과에서 관리자 전용 URL 후보를 수집
def collect_admin_urls(
    crawl_pages: list[dict],
    include_path_patterns: bool = True,
    limit: int | None = None,
) -> list[dict]:
    candidates: list[dict] = []
    seen: set[str] = set()

    for page in crawl_pages:
        url = page.get("url") or ""
        if not url or url in seen or not _is_safe_get_candidate(url):
            continue

        accessible_by = {str(r).lower() for r in page.get("accessible_by", [])}
        admin_only = "admin" in accessible_by and not ({"guest", "member", "member1", "member2", "user"} & accessible_by)

        if admin_only:
            source = "accessible_by_admin_only"
            confidence = "high"
        elif include_path_patterns and ADMIN_PATH_RE.search(urlparse(url).path):
            source = "admin_path_pattern"
            confidence = "low"
        else:
            continue

        seen.add(url)
        candidates.append(
            {
                "url": url,
                "source": source,
                "candidate_confidence": confidence,
                "accessible_by": sorted(accessible_by),
            }
        )

        if limit and len(candidates) >= limit:
            break

    return candidates


# 관리자 URL 후보를 역할별 noop probe task로 변환
def build_vertical_tasks(
    admin_urls: list[dict],
    role_cookies: dict[str, dict],
    roles: tuple[str, ...] = ROLE_ORDER,
) -> list[dict]:
    tasks: list[dict] = []

    for idx, candidate in enumerate(admin_urls, start=1):
        scenario_id = f"bac_vertical_{idx:04d}"
        for role in roles:
            if role not in role_cookies:
                continue

            tasks.append(
                {
                    "id": f"{scenario_id}_{role}",
                    "point": scenario_id,
                    "url": candidate["url"],
                    "method": "GET",
                    "inject_mode": "noop",
                    "inject_location": "query",
                    "inject_param": None,
                    "base_params": {},
                    "base_cookies": role_cookies.get(role) or {},
                    "base_value": "",
                    "payload": None,
                    "meta": {
                        "vuln_type": "bac_vertical",
                        "scenario": "low_role_access_admin_url",
                        "scenario_id": scenario_id,
                        "role": role,
                        "expected_role": "admin",
                        "source": candidate["source"],
                        "candidate_confidence": candidate["candidate_confidence"],
                        "accessible_by": candidate.get("accessible_by", []),
                    },
                }
            )

    return tasks


# 수직 권한 상승 테스트 task를 생성하고 실행 결과를 저장
def run_vertical_probe(
    run_path_fn: Callable[[str], str],
    timeout: int = 10,
    delay: float = 0.0,
    include_path_patterns: bool = True,
    limit: int | None = None,
    progress_callback=None,
) -> list[dict]:
    crawl_file = run_path_fn("crawl_result.json")
    tasks_file = run_path_fn(TASKS_FILE)
    results_file = run_path_fn(RESULTS_FILE)

    crawl_pages = _load_json(crawl_file, [])
    role_cookies = load_cookies(run_path_fn)
    admin_urls = collect_admin_urls(
        crawl_pages,
        include_path_patterns=include_path_patterns,
        limit=limit,
    )
    tasks = build_vertical_tasks(admin_urls, role_cookies)

    os.makedirs(os.path.dirname(tasks_file) or ".", exist_ok=True)
    with open(tasks_file, "w", encoding="utf-8") as f:
        json.dump(tasks, f, ensure_ascii=False, indent=2)

    print(f"[BAC] vertical candidates={len(admin_urls)}, tasks={len(tasks)}")
    print(f"[BAC] tasks saved: {tasks_file}")

    if not tasks:
        with open(results_file, "w", encoding="utf-8") as f:
            json.dump([], f, ensure_ascii=False, indent=2)
        return []

    results = execute(
        tasks,
        timeout=timeout,
        delay=delay,
        output_file=results_file,
        progress_callback=progress_callback,
    )
    print(f"[BAC] results saved: {results_file}")
    return results


# CLI 인자를 파싱하여 수직 권한 상승 테스트를 실행
def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-dir", default="results")
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--delay", type=float, default=0.0)
    parser.add_argument("--include-path-patterns", action="store_true")
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    run_vertical_probe(
        make_run_path_fn(args.run_dir),
        timeout=args.timeout,
        delay=args.delay,
        include_path_patterns=args.include_path_patterns,
        limit=args.limit,
    )


if __name__ == "__main__":
    main()
