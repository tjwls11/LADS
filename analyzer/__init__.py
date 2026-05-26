from __future__ import annotations

import json
import os

from .sqli_analyzer import (
    validate_sqli,
    detect_boolean_group,
    detect_orderby_group,
    detect_probe_group, 
)
from .xss_analyzer  import validate_xss
from .bac_analyzer  import validate_bac, detect_bac_group

__all__ = [
    "run", "validate",
    "validate_sqli", "validate_xss", "validate_bac",
    "detect_boolean_group", "detect_orderby_group", "detect_probe_group", "detect_bac_group",
]


def _vuln_type(r: dict) -> str:
    return ((r.get("meta") or {}).get("vuln_type") or "").lower()


def _make_finding(r: dict, evidence: str) -> dict:
    meta = r.get("meta") or {}
    return {
        "id":          r.get("id"),
        "point":       r.get("point"),
        "url":         r.get("url"),
        "method":      r.get("method"),
        "param":       r.get("inject_param"),
        "payload":     r.get("payload") or "",
        "inject_mode": r.get("inject_mode"),
        "vuln_type":   meta.get("vuln_type"),
        "role":        meta.get("role"), 
        "status":      r.get("status"),
        "elapsed":     r.get("elapsed") or 0.0,
        "evidence":    evidence,
    }


def _validate_single(r: dict) -> tuple[bool, str]:
    vt = _vuln_type(r)
    if "xss" in vt:
        return validate_xss(r)
    if "sqli" in vt or "sql" in vt:
        return validate_sqli(r)
    if "bac" in vt or "broken_access" in vt or "auth" in vt:
        return validate_bac(r)

    ok, ev = validate_xss(r)
    if ok:
        return True, ev
    return validate_sqli(r)


def validate(results: list[dict], progress_callback=None) -> list[dict]:

    findings: list[dict] = []
    found_ids: set = set()
    total = len(results)

    for idx, r in enumerate(results):
        if progress_callback:
            progress_callback(idx + 1, total)

        if r.get("error") or not r.get("response_body"):
            continue

        ok, evidence = _validate_single(r)
        if ok:
            findings.append(_make_finding(r, evidence))
            found_ids.add(r.get("id"))

    group_detectors = [
        detect_boolean_group,
        detect_orderby_group,
        detect_probe_group,
        detect_bac_group,
    ]

    for detector in group_detectors:
        for item in detector(results):
            r        = item["result"]
            evidence = item["evidence"]
            if r.get("id") in found_ids:
                continue
            findings.append(_make_finding(r, evidence))
            found_ids.add(r.get("id"))

    return findings


def run(
    input_file:  str = "results/execution_results.json",
    output_file: str = "results/findings.json",
    progress_callback=None,
) -> list[dict]:
    with open(input_file, encoding="utf-8") as f:
        results = json.load(f)

    findings = validate(results, progress_callback=progress_callback)

    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)

    return findings