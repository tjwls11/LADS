from __future__ import annotations

import json
import os

from .sqli_analyzer import (
    validate_sqli,
    detect_boolean_group, detect_orderby_group, detect_probe_group,
)
from .xss_analyzer import validate_xss
from .bac_analyzer import validate_bac, detect_bac_group, detect_idor_group
from findings import (
    make_finding,
    verdict_to_confidence,
    VERDICT_CONFIRMED, VERDICT_SUSPECTED, VERDICT_CANDIDATE,
    MODULE_XSS, MODULE_SQLI, MODULE_BAC,
    XSS_CONFIRMED, XSS_STORED_CONFIRMED,
    SQLI_CONFIRMED, SQLI_SUSPECTED, SQLI_CANDIDATE,
    BAC_SUSPECTED_LOW, BAC_SUSPECTED_MEDIUM, BAC_SUSPECTED_HIGH,
    IDOR_SUSPECTED,
    HIGH, MEDIUM, LOW,
)

__all__ = [
    "run", "validate",
    "validate_sqli", "validate_xss", "validate_bac",
    "detect_boolean_group", "detect_orderby_group", "detect_probe_group",
    "detect_bac_group", "detect_idor_group",
]


def _vuln_type(r: dict) -> str:
    return ((r.get("meta") or {}).get("vuln_type") or "").lower()


def _resolve_module(vt: str, evidence: str) -> str:
    if "xss" in vt:
        return MODULE_XSS
    if "sqli" in vt or "sql" in vt:
        return MODULE_SQLI
    if "bac" in vt or "broken_access" in vt or "auth" in vt:
        return MODULE_BAC
    # vt 로 못 가르면 evidence 로 추론
    ev = evidence.lower()
    if "xss" in ev:
        return MODULE_XSS
    if "sqli" in ev or "sql" in ev:
        return MODULE_SQLI
    if "bac" in ev or "idor" in ev or "escalation" in ev or "browsing" in ev:
        return MODULE_BAC
    return MODULE_XSS


def _resolve_type(module: str, verdict: str, evidence: str) -> str:
    """
    module + verdict + evidence 로 finding type 을 결정.
    confidence 와 type 이 따로 놀던 문제(항상 _CONFIRMED / 항상 _MEDIUM)를 없앤다.
    """
    ev = evidence.lower()

    if module == MODULE_SQLI:
        if verdict == VERDICT_CONFIRMED:
            return SQLI_CONFIRMED
        if verdict == VERDICT_SUSPECTED:
            return SQLI_SUSPECTED
        return SQLI_CANDIDATE

    if module == MODULE_XSS:
        if "stored xss" in ev or "재조회" in ev:
            return XSS_STORED_CONFIRMED
        return XSS_CONFIRMED

    if module == MODULE_BAC:
        if "idor" in ev:
            return IDOR_SUSPECTED
        if verdict == VERDICT_CONFIRMED:
            return BAC_SUSPECTED_HIGH
        if verdict == VERDICT_SUSPECTED:
            return BAC_SUSPECTED_MEDIUM
        return BAC_SUSPECTED_LOW

    return XSS_CONFIRMED


def _resolve_category(module: str, vt: str, evidence: str) -> str:
    ev = evidence.lower()
    if module == MODULE_SQLI:
        if "time" in ev:
            return "time_based"
        if "error" in ev or "db 에러" in ev or "union" in ev:
            return "error_based"
        if "order by" in ev:
            return "orderby"
        if "boolean" in ev:
            return "boolean"
        return "unknown"
    if module == MODULE_XSS:
        if "stored" in ev or any(x in vt for x in ("subject", "content", "comment")):
            return "stored"
        if "search" in vt or "reflected" in vt or "반사" in ev:
            return "reflected"
        return "unknown"
    if module == MODULE_BAC:
        if "idor" in ev:
            return "idor"
        if "forced_browsing" in ev or "browsing" in ev:
            return "forced_browsing"
        if "escalation" in ev:
            return "vertical_escalation"
        return "access_control"
    return "unknown"


def _make_finding(r: dict, evidence: str, verdict: str) -> dict:
    meta = r.get("meta") or {}
    vt   = (meta.get("vuln_type") or "").lower()

    module     = _resolve_module(vt, evidence)
    type_      = _resolve_type(module, verdict, evidence)
    category   = _resolve_category(module, vt, evidence)
    confidence = verdict_to_confidence(verdict)

    f = make_finding(
        module=module,
        type=type_,
        category=category,
        url=r.get("url") or "",
        param=r.get("inject_param"),
        payload=r.get("payload") or "",
        status=r.get("status"),
        confidence=confidence,
        evidence=evidence,
    )
    f["id"]          = r.get("id")
    f["point"]       = r.get("point")
    f["inject_mode"] = r.get("inject_mode")
    f["elapsed"]     = r.get("elapsed") or 0.0
    f["role"]        = meta.get("role")
    f["verdict"]     = verdict
    return f


def _validate_single(r: dict) -> tuple[bool, str, str]:
    """반환: (취약여부, evidence, verdict)"""
    vt = _vuln_type(r)
    if "xss" in vt:
        return validate_xss(r)
    if "sqli" in vt or "sql" in vt:
        return validate_sqli(r)
    if "bac" in vt or "broken_access" in vt or "auth" in vt:
        return validate_bac(r)

    # vuln_type 불명 — XSS 먼저 시도 후 SQLi
    ok, ev, verdict = validate_xss(r)
    if ok:
        return True, ev, verdict
    return validate_sqli(r)


def validate(results: list[dict], progress_callback=None) -> list[dict]:
    findings: list[dict] = []
    found_ids: set = set()
    total = len(results)

    # Phase 1: 그룹 분석 (짝/역할 비교 = 더 강한 증거 → 우선권, IDOR 포함)
    detectors = [
        detect_boolean_group,
        detect_probe_group,
        detect_orderby_group,
        detect_idor_group,
        detect_bac_group,
    ]
    for detector in detectors:
        for item in detector(results):
            r        = item["result"]
            evidence = item["evidence"]
            verdict  = item.get("verdict", VERDICT_CANDIDATE)
            if r.get("id") in found_ids:
                continue
            findings.append(_make_finding(r, evidence, verdict))
            found_ids.add(r.get("id"))

    # Phase 2: 단건 판정 (그룹에서 못 잡은 것 보충)
    for idx, r in enumerate(results):
        if progress_callback:
            progress_callback(idx + 1, total)
        if r.get("error") or not r.get("response_body"):
            continue
        if r.get("id") in found_ids:
            continue
        ok, evidence, verdict = _validate_single(r)
        if ok:
            findings.append(_make_finding(r, evidence, verdict))
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