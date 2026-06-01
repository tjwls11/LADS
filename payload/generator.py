import json
import argparse
import sys
import os
from dotenv import load_dotenv
load_dotenv()

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from .llm_client import LLMClient
    from .prompt_builder import SYSTEM_PROMPT, build_mutation_prompt
    from .parser import parse as parse_llm
    from .baseline import sqli as baseline_sqli
    from .baseline import xss as baseline_xss
    from .point_builder import build_points_from_targets
except ImportError:
    from llm_client import LLMClient
    from prompt_builder import SYSTEM_PROMPT, build_mutation_prompt
    from parser import parse as parse_llm
    from baseline import sqli as baseline_sqli
    from baseline import xss as baseline_xss
    from point_builder import build_points_from_targets

from payload.validator import filter_payloads, deduplicate


COUNT = 7
BASELINE_LIMIT = 8


def _sample_diverse(payloads: list[dict], limit: int) -> list[dict]:
    """타입별 round-robin 샘플링 — 단순 슬라이싱으로 생기는 단일 타입 편중 방지."""
    from collections import defaultdict
    by_type: dict[str, list[dict]] = defaultdict(list)
    for p in payloads:
        by_type[p.get("type", "unknown")].append(p)

    result: list[dict] = []
    groups = list(by_type.values())
    i = 0
    while len(result) < limit and any(groups):
        g = groups[i % len(groups)]
        if g:
            result.append(g.pop(0))
        i += 1
    return result


def _select_baseline_payloads(point: dict, vuln_type: str) -> list[dict]:
    vt = (vuln_type or "").lower()
    value_shape = (point.get("value_shape") or "").lower()
    field_type  = (point.get("field_type")  or "").lower()
    location    = (point.get("location")    or "").lower()

    if vt == "sqli_login":
        payloads = baseline_sqli.get_by_sql_context("auth", "HIGH")
    elif vt == "sqli_field":
        payloads = baseline_sqli.get_by_sql_context("field_selector", "HIGH")
    elif vt == "sqli_orderby":
        payloads = baseline_sqli.get_by_sql_context("orderby", "HIGH")
    elif vt.startswith("sqli_"):
        if value_shape == "number_like":
            payloads = baseline_sqli.get_by_context("numeric", "HIGH")
        else:
            payloads = baseline_sqli.get_by_context("string", "HIGH")
    elif vt == "xss_search":
        if field_type == "textarea":
            payloads = baseline_xss.get_by_context("body", "HIGH")
        else:
            payloads = baseline_xss.get_by_context("attr_value", "HIGH")
    elif vt in {"xss_subject", "xss_content", "xss_comment"}:
        if field_type == "textarea":
            payloads = baseline_xss.get_by_context("body", "HIGH")
        else:
            payloads = baseline_xss.get_by_context("stored", "HIGH")
    elif vt.startswith("xss_"):
        if location in ("header", "cookie"):
            payloads = baseline_xss.get_by_context("filter_bypass", "HIGH")
        elif field_type == "textarea":
            payloads = baseline_xss.get_by_context("body", "HIGH")
        else:
            payloads = baseline_xss.get_by_context("reflected", "HIGH")
    else:
        payloads = []

    return _sample_diverse(payloads, BASELINE_LIMIT)


def generate_payloads(
    points: list[dict],
    client: LLMClient,
    progress_callback=None,
) -> dict:
    all_results: dict = {}
    total_points = len(points)
    # (group_key, vuln_type) → 동일 파라미터 그룹의 LLM 결과 재사용
    payload_cache: dict[tuple[str, str], list[dict]] = {}

    for idx, point in enumerate(points):
        pname = point["name"]
        if progress_callback:
            progress_callback(idx, total_points)
        print(f"\n[INPUT POINT] {pname}")
        print(f"  {point['method']} {point['url']} | param={point['param']}")
        print(f"  Note: {point['note']}")
        print("-" * 60)

        all_results[pname] = {}

        for vtype in point["vuln_types"]:
            cache_key = (point.get("group_key") or pname, vtype)
            if cache_key in payload_cache:
                records = payload_cache[cache_key]
                all_results[pname][vtype] = records
                print(f"  [{vtype}] reused group payloads ({len(records)} payloads)")
                continue

            print(f"  [{vtype}] generating group payloads...", end=" ", flush=True)
            try:
                baseline_payloads = _select_baseline_payloads(point, vtype)
                if not baseline_payloads:
                    payload_cache[cache_key] = []
                    all_results[pname][vtype] = []
                    print("skipped: no baseline")
                    continue

                prompt = build_mutation_prompt(point, vtype, baseline_payloads, count=COUNT)
                raw = client.generate(prompt=prompt, system=SYSTEM_PROMPT, temperature=0.7)
                parsed = parse_llm(raw)
                filtered, rejected = filter_payloads(parsed)
                records = deduplicate(filtered)
                payload_cache[cache_key] = records
                all_results[pname][vtype] = records
                print(f"{len(records)} payloads (제거: {len(rejected)}개)")
                for r in records:
                    print(f"    [{r['type']:20s}] {r['payload'][:70]}")
            except Exception as e:
                print(f"FAILED: {e}")
                all_results[pname][vtype] = []

        print()

    return all_results


def run(out_file: str = "results/payloads_llm.json", progress_callback=None, targets_file: str | None = None):

    print(f"\n{'='*60}")
    print(f"  Payload Generator")
    print(f"{'='*60}\n")

    if not targets_file or not os.path.exists(targets_file):
        print(f"[ERROR] targets_file 없음: {targets_file}")
        print("[ERROR] 크롤링을 먼저 실행하세요.")
        return

    with open(targets_file, encoding="utf-8") as f:
        targets_data = json.load(f)

    points = build_points_from_targets(targets_data)
    if not points:
        print("[ERROR] injectable 파라미터 없음 — targets.json을 확인하세요.")
        return

    print(f"  입력점: {len(points)}개 (targets.json 기반)\n")

    all_results = generate_payloads(points, LLMClient(), progress_callback)

    os.makedirs(os.path.dirname(out_file) or ".", exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(all_results, f, ensure_ascii=False, indent=2)

    meta_out = (out_file[:-5] if out_file.endswith(".json") else out_file) + "_meta.json"
    os.makedirs(os.path.dirname(meta_out) or ".", exist_ok=True)
    with open(meta_out, "w", encoding="utf-8") as f:
        json.dump(points, f, ensure_ascii=False, indent=2)

    total = sum(len(r) for pd in all_results.values() for r in pd.values())

    print(f"{'='*60}")
    print(f"  저장 완료 -> {out_file}")
    print(f"  총 페이로드: {total}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default="results/payloads_llm.json")
    parser.add_argument("--targets", default=None)
    args = parser.parse_args()
    run(args.out, targets_file=args.targets)
