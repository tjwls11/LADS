import json
import os
from urllib.parse import urlparse
from dataclasses import asdict
from crawl.auth import login_all_roles
from crawl.crawler import Crawler
from crawl.target_builder import build_targets
from probe.strategy import build_tasks
from bac.vertical import run_vertical_probe

TASK_LABELS = {
    "crawl":    "크롤링 및 타깃 구성",
    "payload":  "페이로드 생성",
    "probe":    "주입 테스트 준비",
    "execute":  "퍼징 실행",
    "validate": "취약점 판정",
    "misconfig": "설정 오류 점검",
    "all":      "전체 진단",
}

def _prog(emit_progress, n):
    if emit_progress:
        emit_progress(n)


# 역할별 크롤 결과를 URL 기준으로 병합하고 accessible_by(어떤 역할에서 접근 가능한지) 태깅
def _merge_crawl_results(role_pages: dict[str, list[dict]]) -> list[dict]:
    
    def _form_sig(form: dict) -> str:
        path = urlparse(form.get("action", "")).path or form.get("action", "")
        method = form.get("method", "GET").upper()
        names = sorted(f["name"] for f in form.get("fields", []) if f.get("name"))
        return f"{method}:{path}:{','.join(names)}"

    url_map: dict[str, dict] = {}

    for role, pages in role_pages.items():
        for page in pages:
            url = page["url"]
            status = page.get("status_code", 0)

            if url not in url_map:
                url_map[url] = {**page, "accessible_by": []}

            # 해당 역할이 200으로 접근 가능한 경우 기록
            if status == 200 and role not in url_map[url]["accessible_by"]:
                url_map[url]["accessible_by"].append(role)

            # 이미 저장된 폼 시그니처와 비교해 새 폼만 추가한다
            existing_sigs = {_form_sig(f) for f in url_map[url].get("forms", [])}
            for form in page.get("forms", []):
                sig = _form_sig(form)
                if sig not in existing_sigs:
                    url_map[url].setdefault("forms", []).append(form)
                    existing_sigs.add(sig)

    return list(url_map.values())


def _task_crawl(run_path_fn, target_url, emit_progress=None):
    crawl_file   = run_path_fn("crawl_result.json")
    targets_file = run_path_fn("targets.json")

    # 역할별 세션 쿠키 획득
    role_sessions = login_all_roles(base_url=target_url)
    acquired = [r for r in role_sessions if role_sessions[r] or r == "guest"]
    print(f"[CRAWL] roles to crawl: {acquired}")

    with open(run_path_fn("auth_cookies_roles.json"), "w", encoding="utf-8") as f:
        json.dump(role_sessions, f, ensure_ascii=False, indent=2)

    # 역할별 크롤 실행
    role_pages: dict[str, list[dict]] = {}
    n_roles = max(len(role_sessions), 1)
    prog_per_role = 18 // n_roles

    for i, (role, cookies) in enumerate(role_sessions.items()):
        if role == "member2":
            continue
        print(f"[CRAWL] [{role}] start: {target_url}")
        crawler = Crawler(target_url, init_cookies=cookies)

        base = i * prog_per_role
        def _crawl_progress(done, total, _base=base):
            _prog(emit_progress, _base + int(done / max(total, 1) * prog_per_role))

        crawler.crawl(progress_callback=_crawl_progress)
        crawler.summary()
        role_pages[role] = [asdict(r) for r in crawler.results]
        print(f"[CRAWL] [{role}] pages={len(crawler.results)}")

    _prog(emit_progress, 18)

    # 병합 및 accessible_by 태깅
    merged_pages = _merge_crawl_results(role_pages)
    print(f"[CRAWL] merged: {len(merged_pages)} unique pages")

    os.makedirs(os.path.dirname(crawl_file) or ".", exist_ok=True)
    with open(crawl_file, "w", encoding="utf-8") as f:
        json.dump(merged_pages, f, ensure_ascii=False, indent=2)
    print(f"[CRAWL] saved: {crawl_file}")

    _prog(emit_progress, 20)

    targets = build_targets(merged_pages)
    with open(targets_file, "w", encoding="utf-8") as f:
        json.dump(targets, f, ensure_ascii=False, indent=2)
    print(f"[CRAWL] targets saved: {targets_file} ({len(targets)})")


def _task_payload(payloads_file, targets_file=None, emit_progress=None):
    from payload.generator import run as generate_run
    os.makedirs("results", exist_ok=True)
    print(f"[PAYLOAD] generate: {payloads_file}")

    def _payload_cb(idx, total):
        _prog(emit_progress, 20 + int(idx / max(total, 1) * 10))

    generate_run(out_file=payloads_file, targets_file=targets_file, progress_callback=_payload_cb)
    _prog(emit_progress,30)


def _task_probe(run_path_fn, payloads_file, emit_progress=None):
    targets_file     = run_path_fn("targets.json")
    probe_tasks_file = run_path_fn("probe_tasks.json")

    if not os.path.exists(payloads_file):
        print(f"[ERROR] missing payload file: {payloads_file}")
        return
    if not os.path.exists(targets_file):
        print(f"[ERROR] missing targets file: {targets_file}")
        return

    with open(payloads_file, encoding="utf-8") as f:
        payloads = json.load(f)
    with open(targets_file, encoding="utf-8") as f:
        targets = json.load(f)

    base_cookie: dict = {}
    roles_file = run_path_fn("auth_cookies_roles.json")
    if os.path.exists(roles_file):
        with open(roles_file, encoding="utf-8") as f:
            base_cookie = json.load(f).get("member") or {}
        print(f"[PROBE] 일반 유저 로그인됨")
    else:
        print("[PROBE] 인증 파일 없음. 인증없이 진행")

    tasks = build_tasks(payloads, targets, base_cookie=base_cookie)
    with open(probe_tasks_file, "w", encoding="utf-8") as f:
        json.dump(tasks, f, ensure_ascii=False, indent=2)
    print(f"[PROBE] tasks saved: {probe_tasks_file} ({len(tasks)})")
    _prog(emit_progress, 35)


def _task_execute(run_path_fn, emit_progress=None):
    from probe.executor import execute

    probe_tasks_file = run_path_fn("probe_tasks.json")
    exec_file       = run_path_fn("execution_results.json")

    if not os.path.exists(probe_tasks_file):
        print(f"[ERROR] missing probe task file: {probe_tasks_file}")
        return

    with open(probe_tasks_file, encoding="utf-8") as f:
        tasks = json.load(f)

    def _execute_progress(done, total):
        _prog(emit_progress, 35 + int(done / max(total, 1) * 50))

    print(f"[EXEC] start: {len(tasks)} tasks")
    results = execute(tasks, timeout=10, delay=0.0, output_file=exec_file, progress_callback=_execute_progress)
    ok      = sum(1 for r in results if r.get("error") is None)
    timeout = sum(1 for r in results if r.get("error") == "timeout")
    err     = sum(1 for r in results if r.get("error") and r.get("error") != "timeout")
    print(f"[EXEC] done: ok={ok}, timeout={timeout}, error={err}")
    _prog(emit_progress, 85)


def _task_bac_vertical(run_path_fn, target_url=None, emit_progress=None):
    crawl_file = run_path_fn("crawl_result.json")
    if not os.path.exists(crawl_file):
        print(f"[BAC] missing crawl result file: {crawl_file}")
        return

    if target_url:
        from crawl.auth import login_all_roles
        print("[BAC] refreshing session cookies before vertical probe")
        role_sessions = login_all_roles(base_url=target_url)
        with open(run_path_fn("auth_cookies_roles.json"), "w", encoding="utf-8") as f:
            json.dump(role_sessions, f, ensure_ascii=False, indent=2)

    results = run_vertical_probe(
        run_path_fn,
        progress_callback=lambda done, total: _prog(emit_progress, int(done / max(total, 1) * 100)),
    )
    print(f"[BAC] vertical done: {len(results)} results")
    _prog(emit_progress, 90)


def _task_validate(run_path_fn, emit_progress=None): 
    from analyzer import run as validate_run

    exec_file     = run_path_fn("execution_results.json")
    findings_file = run_path_fn("findings.json")

    if not os.path.exists(exec_file):
        print(f"[ERROR] missing execution result file: {exec_file}")
        return

    def _validate_progress(done, total):
        _prog(emit_progress, 90 + int(done / max(total, 1) * 10))

    findings = validate_run(input_file=exec_file, output_file=findings_file, progress_callback=_validate_progress)
    xss_cnt  = sum(1 for f in findings if "xss" in (f.get("vuln_type") or "").lower())
    sqli_cnt = sum(1 for f in findings if "sql" in (f.get("vuln_type") or "").lower())
    print(f"[VALIDATE] done: findings={len(findings)}, xss={xss_cnt}, sqli={sqli_cnt}")
    _prog(emit_progress, 95)


def _task_misconfig(run_path_fn, target_url, emit_progress=None):
    from misconfig.checker import run as misconfig_run

    findings_file = run_path_fn("findings.json")

    print(f"[MISCONFIG] target: {target_url}")
    findings = misconfig_run(
        base_url=target_url,
        output_file=findings_file,
        progress_callback=lambda done, total: _prog(emit_progress, int(done / max(total, 1) * 100)),
        append=True,
    )
    confirmed = sum(1 for f in findings if f.get("type") == "MISCONFIG_CONFIRMED")
    warnings  = sum(1 for f in findings if f.get("type") == "MISCONFIG_WARNING")
    print(f"[MISCONFIG] confirmed={confirmed}, warning={warnings}")
    _prog(emit_progress, 100)


def _task_all(run_path_fn, target_url, payloads_file, skip_crawl=False, emit_progress=None):

    _prog(emit_progress, 2)

    if skip_crawl:
        print("[CRAWL] 이전 크롤링 결과 재사용")
        _prog(emit_progress, 20)
    else:
        _task_crawl(run_path_fn, target_url, emit_progress)
        _prog(emit_progress, 20)

    if not os.path.exists(run_path_fn("crawl_result.json")):
        print("[ERROR] 크롤링 결과 파일 없음 — 스캔 중단")
        return

    if os.path.exists(payloads_file):
        try:
            with open(payloads_file, encoding="utf-8") as _f:
                _cnt = len(json.load(_f))
        except Exception:
            _cnt = 0
        print(f"[PAYLOAD] 기존 페이로드 재사용 ({_cnt}개) — 새로 생성하려면 파일 삭제 후 재스캔")
        _prog(emit_progress, 30)
    else:
        _task_payload(payloads_file, targets_file=run_path_fn("targets.json"), emit_progress=emit_progress)
        _prog(emit_progress, 30)

    if not os.path.exists(payloads_file):
        print("[ERROR] 페이로드 파일 없음 — 스캔 중단")
        return

    _task_probe(run_path_fn, payloads_file, emit_progress)
    _prog(emit_progress, 35)

    if not os.path.exists(run_path_fn("probe_tasks.json")):
        print("[ERROR] 퍼징 작업 파일 없음 — 스캔 중단")
        return

    _task_execute(run_path_fn, emit_progress)
    _prog(emit_progress, 85)

    if not os.path.exists(run_path_fn("execution_results.json")):
        print("[ERROR] 실행 결과 파일 없음 — 스캔 중단")
        return
    
    _task_bac_vertical(
        run_path_fn,
        target_url=target_url,
        emit_progress=lambda pct: _prog(emit_progress, 85 + int(pct * 5 / 100)),
    )
    _prog(emit_progress, 90)

    _task_validate(
        run_path_fn,
        emit_progress=lambda pct: _prog(emit_progress, 90 + int((pct - 90) * 5 / 10)),
    )
    _prog(emit_progress, 95)

    _task_misconfig(
        run_path_fn,
        target_url,
        emit_progress=lambda pct: _prog(emit_progress, 95 + int(pct * 5 / 100)),
    )
    _prog(emit_progress, 100)

