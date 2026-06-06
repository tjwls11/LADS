"""
DVWA Pipeline Integration Test
크롤러는 건너뛰고 수동 crawl_result.json을 생성한 뒤
target_builder → strategy → executor → analyzer 실제 파이프라인을 검증한다.

실행:  python scripts/dvwa_pipeline_test.py
종료:  0=정상, 1=파이프라인 오류
"""

from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path

# ── 경로 설정: scripts/ 아래에서 실행해도 프로젝트 루트 기준으로 동작 ──────────
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)

from crawl.target_builder import build_targets         # noqa: E402
from probe.strategy        import build_tasks           # noqa: E402
from probe.executor        import execute               # noqa: E402
import analyzer                                         # noqa: E402
from utilities             import save_json             # noqa: E402

# ── 상수 ──────────────────────────────────────────────────────────────────────

DVWA        = "http://localhost:8080"
PHPSESSID   = "meddestejdkednsp7be80j0k30"
BASE_COOKIE = {"security": "low", "PHPSESSID": PHPSESSID}

CRAWL_FILE    = "results/crawl_result.json"
TARGETS_FILE  = "results/targets.json"
TASKS_FILE    = "results/tasks_dvwa.json"
RESULTS_FILE  = "results/results_dvwa.json"
FINDINGS_FILE = "results/findings_dvwa.json"
SUMMARY_FILE  = "results/dvwa_pipeline_summary.txt"

# ── Step 1: 수동 crawl_result.json ───────────────────────────────────────────
#
# XSS 페이지는 query_params 대신 form으로 정의한다.
# target_builder가 field_type="text" 를 보고 sqli_string + xss_search 를 추론하며,
# query_params의 url_param 타입은 sqli_string 만 추론하므로 XSS 태스크가 생략된다.

CRAWL_PAGES: list[dict] = [
    {
        "url":         f"{DVWA}/vulnerabilities/sqli/?id=1&Submit=Submit",
        "status_code": 200,
        "forms":       [],
        "links":       [],
        "danger_links": [],
        "query_params": {
            "id":     ["1"],
            "Submit": ["Submit"],
        },
        "page_title":    "DVWA SQL Injection",
        "is_error_page": False,
    },
    {
        "url":         f"{DVWA}/vulnerabilities/xss_r/?name=test",
        "status_code": 200,
        # form으로 정의해야 field_type=text → xss_search 추론이 동작한다
        "forms": [
            {
                "action":  "/vulnerabilities/xss_r/",
                "method":  "GET",
                "enctype": "application/x-www-form-urlencoded",
                "fields": [
                    {"name": "name", "field_type": "text", "value": "test"},
                ],
            }
        ],
        "links":       [],
        "danger_links": [],
        "query_params": {},   # form이 커버하므로 URL 파라미터로 중복 생성 안 함
        "page_title":    "DVWA Reflected XSS",
        "is_error_page": False,
    },
]


def step1_write_crawl() -> None:
    os.makedirs("results", exist_ok=True)
    save_json(CRAWL_FILE, CRAWL_PAGES)


# ── Step 2: target_builder ────────────────────────────────────────────────────

def step2_build_targets() -> list[dict]:
    targets = build_targets(CRAWL_PAGES)
    save_json(TARGETS_FILE, targets)
    return targets


# ── Step 3+4: strategy ────────────────────────────────────────────────────────

def step34_build_tasks(targets: list[dict]) -> list[dict]:
    tasks = build_tasks(targets, base_cookie=BASE_COOKIE)
    save_json(TASKS_FILE, tasks)
    return tasks


# ── Step 5: executor ──────────────────────────────────────────────────────────

def step5_execute(tasks: list[dict]) -> list[dict]:
    results = execute(tasks, workers=3, output_file=RESULTS_FILE)
    return results


# ── Step 6: analyzer ─────────────────────────────────────────────────────────

def step6_analyze(results: list[dict]) -> list[dict]:
    findings = analyzer.validate(results)
    save_json(FINDINGS_FILE, findings)
    return findings


# ── Step 7: summary ───────────────────────────────────────────────────────────

_META_TYPE_ORDER = {"BASELINE": 0, "BOOLEAN": 1, "ERROR_BASED": 2, "TIME_BASED": 3}


def _conf_counts(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        k = (f.get("confidence") or "").upper()
        if k in counts:
            counts[k] += 1
    return counts


def _finding_lines(findings: list[dict]) -> list[str]:
    if not findings:
        return ["  (없음)"]
    lines = []
    for f in findings:
        conf     = (f.get("confidence") or "?").upper()
        category = f.get("category") or "?"
        param    = f.get("param") or "?"
        evidence = (f.get("evidence") or "")[:90]
        lines.append(f"  [{conf:6s}] {category:15s}  param={param}  {evidence}")
    return lines


def step7_summary(
    targets:  list[dict],
    tasks:    list[dict],
    results:  list[dict],
    findings: list[dict],
) -> None:
    sqli_findings = [f for f in findings if (f.get("module") or "").lower() == "sqli"]
    xss_findings  = [f for f in findings if (f.get("module") or "").lower() == "xss"]
    conf          = _conf_counts(findings)

    # id 파라미터 태스크: baseline / true / false / error / time 순서 확인용
    id_tasks = sorted(
        [t for t in tasks if t.get("inject_param") == "id"],
        key=lambda t: _META_TYPE_ORDER.get((t.get("meta") or {}).get("type", ""), 99),
    )

    lines = [
        "DVWA Pipeline Integration Test — Summary",
        f"Generated : {datetime.now().isoformat(timespec='seconds')}",
        "=" * 64,
        f"Targets   : {len(targets)}",
        f"Tasks     : {len(tasks)}",
        f"Results   : {len(results)}",
        "",
        "── SQLi id 파라미터 task 목록 (type 순) ────────────────────",
    ]

    for t in id_tasks:
        meta    = t.get("meta") or {}
        ttype   = (meta.get("type") or "?")
        family  = (meta.get("family") or "?")
        payload = (t.get("payload") or "")[:60]
        lines.append(f"  [{ttype:12s}] {family:28s}  {payload}")

    lines += [
        "",
        "── Findings ────────────────────────────────────────────────",
        f"  SQLi : {len(sqli_findings)}",
        f"  XSS  : {len(xss_findings)}",
        "",
        "── Confidence ──────────────────────────────────────────────",
        f"  HIGH   : {conf['HIGH']}",
        f"  MEDIUM : {conf['MEDIUM']}",
        f"  LOW    : {conf['LOW']}",
        "",
        "── SQLi Findings ───────────────────────────────────────────",
        *_finding_lines(sqli_findings),
        "",
        "── XSS Findings ────────────────────────────────────────────",
        *_finding_lines(xss_findings),
    ]

    Path(SUMMARY_FILE).write_text("\n".join(lines), encoding="utf-8")


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    step1_write_crawl()
    targets  = step2_build_targets()
    tasks    = step34_build_tasks(targets)
    results  = step5_execute(tasks)
    findings = step6_analyze(results)
    step7_summary(targets, tasks, results, findings)

    for label, path in [
        ("crawl_result ", CRAWL_FILE),
        ("targets      ", TARGETS_FILE),
        ("tasks        ", TASKS_FILE),
        ("results      ", RESULTS_FILE),
        ("findings     ", FINDINGS_FILE),
        ("summary      ", SUMMARY_FILE),
    ]:
        print(f"{label}: {path}")

    # 파이프라인이 실행됐지만 결과가 아무것도 없으면 설정 문제
    if not results:
        print("[WARN] executor returned 0 results — DVWA 연결 및 세션 쿠키를 확인하세요.", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
