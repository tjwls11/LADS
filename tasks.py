import json
import os
from urllib.parse import urlparse
from dataclasses import asdict
from crawl.auth import login_all_roles
from crawl.crawler import Crawler
from crawl.target_builder import build_targets
from probe.strategy import build_tasks
from bac.vertical import run_vertical_probe
from payload.generator import run as generate_run
from analyzer import validate as analyze_results
from findings import save_findings
from probe.executor import execute
from misconfig.checker import run as misconfig_run


TASK_LABELS = {
    "crawl":    "크롤링 및 타깃 구성",
    "payload":  "페이로드 생성",
    "probe":    "주입 테스트 준비",
    "execute":  "퍼징 실행",
    "validate": "취약점 판정",
    "misconfig": "설정 오류 점검",
    "bac":      "BAC 수직 권한 상승 테스트",
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
    print(f"[CRAWL] 현재 로그인 세션: {acquired}")

    with open(run_path_fn("auth_cookies_roles.json"), "w", encoding="utf-8") as f:
        json.dump(role_sessions, f, ensure_ascii=False, indent=2)

    # 역할별 크롤 실행
    role_pages: dict[str, list[dict]] = {}
    n_roles = max(len(role_sessions), 1)
    prog_per_role = 18 // n_roles

    for i, (role, cookies) in enumerate(role_sessions.items()):
        if role in ("member2", "admin"):
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
    print(f"[CRAWL] {len(merged_pages)} 페이지 발견됨")

    os.makedirs(os.path.dirname(crawl_file) or ".", exist_ok=True)
    with open(crawl_file, "w", encoding="utf-8") as f:
        json.dump(merged_pages, f, ensure_ascii=False, indent=2)
    print(f"[CRAWL] 저장됨: {crawl_file}")

    _prog(emit_progress, 20)

    targets = build_targets(merged_pages)
    with open(targets_file, "w", encoding="utf-8") as f:
        json.dump(targets, f, ensure_ascii=False, indent=2)
    print(f"[CRAWL] 타겟 정보 저장됨: {targets_file} ({len(targets)})")


def _task_payload(payloads_file, targets_file=None, emit_progress=None):
    os.makedirs("results", exist_ok=True)
    print(f"[PAYLOAD] 생성됨: {payloads_file}")

    def _payload_cb(idx, total):
        _prog(emit_progress, 20 + int(idx / max(total, 1) * 10))

    generate_run(out_file=payloads_file, targets_file=targets_file, progress_callback=_payload_cb)
    _prog(emit_progress,30)


def _task_probe(run_path_fn, payloads_file, emit_progress=None):
    targets_file     = run_path_fn("targets.json")
    probe_tasks_file = run_path_fn("probe_tasks.json")

    if not os.path.exists(payloads_file):
        print(f"[ERROR] 페이로드 파일이 없음: {payloads_file}")
        return
    if not os.path.exists(targets_file):
        print(f"[ERROR] 크롤링한 파일이 없음: {targets_file}")
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
    probe_tasks_file = run_path_fn("probe_tasks.json")
    exec_file       = run_path_fn("execution_results.json")

    if not os.path.exists(probe_tasks_file):
        print(f"[ERROR] 주입 작업 파일 없음: {probe_tasks_file}")
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
        print(f"[BAC] 크롤링 결과 파일 없음: {crawl_file}")
        return

    if target_url:
        from crawl.auth import login_all_roles
        print("[BAC] refreshing session cookies before vertical probe")
        refreshed = login_all_roles(base_url=target_url)

        roles_file = run_path_fn("auth_cookies_roles.json")
        existing: dict = {}
        if os.path.exists(roles_file):
            with open(roles_file, encoding="utf-8") as f:
                existing = json.load(f)

        # 로그인 성공한 role만 덮어쓰고, 실패한 role은 기존 쿠키 유지
        for role, cookies in refreshed.items():
            if cookies:
                existing[role] = cookies
                print(f"[BAC] {role} 쿠키 갱신됨")
            elif role not in existing:
                existing[role] = {}

        with open(roles_file, "w", encoding="utf-8") as f:
            json.dump(existing, f, ensure_ascii=False, indent=2)

    results = run_vertical_probe(
        run_path_fn,
        progress_callback=lambda done, total: _prog(emit_progress, int(done / max(total, 1) * 100)),
    )
    print(f"[BAC] vertical done: {len(results)} results")
    _prog(emit_progress, 90)


def _task_bac_crawl(run_path_fn, target_url, emit_progress=None):
    crawl_file   = run_path_fn("crawl_result.json")
    targets_file = run_path_fn("targets.json")

    role_sessions = login_all_roles(base_url=target_url)
    acquired = [r for r in role_sessions if role_sessions[r] or r == "guest"]
    print(f"[BAC CRAWL] 세션: {acquired}")

    os.makedirs(os.path.dirname(crawl_file) or ".", exist_ok=True)
    with open(run_path_fn("auth_cookies_roles.json"), "w", encoding="utf-8") as f:
        json.dump(role_sessions, f, ensure_ascii=False, indent=2)

    role_pages: dict[str, list[dict]] = {}
    n_roles = max(len(role_sessions), 1)
    prog_per_role = 18 // n_roles

    for i, (role, cookies) in enumerate(role_sessions.items()):
        if role == "member2":
            continue
        print(f"[BAC CRAWL] [{role}] start: {target_url}")
        crawler = Crawler(target_url, init_cookies=cookies)

        base = i * prog_per_role
        def _crawl_progress(done, total, _base=base):
            _prog(emit_progress, _base + int(done / max(total, 1) * prog_per_role))

        crawler.crawl(progress_callback=_crawl_progress)
        crawler.summary()
        role_pages[role] = [asdict(r) for r in crawler.results]
        print(f"[BAC CRAWL] [{role}] pages={len(crawler.results)}")

    _prog(emit_progress, 18)

    merged_pages = _merge_crawl_results(role_pages)
    print(f"[BAC CRAWL] {len(merged_pages)} 페이지 발견됨")

    with open(crawl_file, "w", encoding="utf-8") as f:
        json.dump(merged_pages, f, ensure_ascii=False, indent=2)

    _prog(emit_progress, 20)

    targets = build_targets(merged_pages)
    with open(targets_file, "w", encoding="utf-8") as f:
        json.dump(targets, f, ensure_ascii=False, indent=2)
    print(f"[BAC CRAWL] 타겟 저장됨: {targets_file} ({len(targets)}개)")


def _task_bac(run_path_fn, target_url=None, emit_progress=None):
    # 1. BAC 전용 크롤링 (3세션: guest + member + admin)
    _task_bac_crawl(run_path_fn, target_url,
                    emit_progress=lambda pct: _prog(emit_progress, int(pct * 20 / 20)))

    # 2. 수직 권한 상승 프로브 (크롤 시 이미 쿠키 갱신됨, 재로그인 불필요)
    _task_bac_vertical(run_path_fn, target_url=None,
                       emit_progress=lambda pct: _prog(emit_progress, 20 + int(pct * 70 / 100)))

    bac_results_file = run_path_fn("bac_vertical_results.json")
    bac_findings_file = run_path_fn("bac_findings.json")

    if not os.path.exists(bac_results_file):
        print("[BAC] 실행 결과 없음 — 분석 건너뜀")
        _prog(emit_progress, 100)
        return

    with open(bac_results_file, encoding="utf-8") as f:
        results = json.load(f)

    findings = analyze_results(results)
    save_findings(findings, bac_findings_file)
    bac_cnt = sum(1 for f in findings if f.get("module") == "bac")
    print(f"[BAC] 분석 완료: findings={len(findings)}, bac={bac_cnt}")
    _prog(emit_progress, 100)


def _task_validate(run_path_fn, emit_progress=None):
    exec_file     = run_path_fn("execution_results.json")
    findings_file = run_path_fn("findings.json")

    if not os.path.exists(exec_file):
        print(f"[ERROR] 실행 결과 파일이 없음: {exec_file}")
        return

    with open(exec_file, encoding="utf-8") as f:
        results = json.load(f)

    def _validate_progress(done, total):
        _prog(emit_progress, 90 + int(done / max(total, 1) * 10))

    findings = analyze_results(results, progress_callback=_validate_progress)
    save_findings(findings, findings_file)

    xss_cnt  = sum(1 for f in findings if f.get("module") == "xss")
    sqli_cnt = sum(1 for f in findings if f.get("module") == "sqli")
    bac_cnt  = sum(1 for f in findings if f.get("module") == "bac")
    print(f"[VALIDATE] done: findings={len(findings)}, xss={xss_cnt}, sqli={sqli_cnt}, bac={bac_cnt}")
    _prog(emit_progress, 95)


def _task_misconfig(run_path_fn, target_url, emit_progress=None):
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

    _task_validate(
        run_path_fn,
        emit_progress=lambda pct: _prog(emit_progress, 85 + int((pct - 90) * 10 / 10)),
    )
    _prog(emit_progress, 95)

    _task_misconfig(
        run_path_fn,
        target_url,
        emit_progress=lambda pct: _prog(emit_progress, 95 + int(pct * 5 / 100)),
    )
    _prog(emit_progress, 100)
