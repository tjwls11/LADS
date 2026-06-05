from __future__ import annotations

from .sqli_analyzer import (
    validate_sqli,
    detect_error_group,
    detect_boolean_group,
    detect_time_group,
    detect_orderby_group,
    detect_probe_group,
)
from .xss_analyzer import validate_xss
from .bac_analyzer import validate_bac, detect_bac_group
from utilities import load_json, save_json
from findings import (
    make_finding,
    sqli_finding_from_verdict,
    MODULE_XSS, MODULE_SQLI, MODULE_BAC,
    XSS_REFLECTED, XSS_STORED_REFLECTED, XSS_SUSPICIOUS,
    SQLI_CONFIRMED, SQLI_SUSPECTED, SQLI_CANDIDATE, SQLI_INFORMATIONAL,
    BAC_SUSPECTED_MEDIUM,
    HIGH, MEDIUM, LOW,
)

__all__ = [
    "run", "validate",
    "validate_sqli", "validate_xss", "validate_bac",
    "detect_error_group", "detect_boolean_group", "detect_time_group",
    "detect_orderby_group", "detect_probe_group", "detect_bac_group",
]


def _vuln_type(r: dict) -> str:
    return ((r.get("meta") or {}).get("vuln_type") or "").lower()


def _derive_module(vt: str) -> str:
    if "xss" in vt:
        return MODULE_XSS
    if "sqli" in vt or "sql" in vt:
        return MODULE_SQLI
    if "bac" in vt or "broken_access" in vt or "auth" in vt:
        return MODULE_BAC
    return MODULE_XSS


def _derive_category(module: str, vt: str, evidence: str) -> str:
    ev = evidence.lower()

    if module == MODULE_SQLI:
        if any(x in ev for x in ("order by", "orderby", "order_by", "unknown column")):
            return "order_by"
        if any(x in ev for x in ("time", "delay", "sleep")):
            return "time_based"
        if any(x in ev for x in ("boolean", "true/false", "true_len", "false_len")):
            return "boolean"
        if any(x in ev for x in ("union", "column count", "select statements")):
            return "union_based"
        if any(x in ev for x in ("sqlstate", "mysql", "syntax", "db 에러", "db error")):
            return "error_based"
        return "unknown"

    if module == MODULE_XSS:
        if "stored" in ev or "stored" in vt or any(x in vt for x in ("subject", "content", "comment")):
            return "stored"
        if "verified" in ev or "playwright" in ev:
            return "verified"
        if "suspicious" in ev or "safe context" in ev:
            return "suspicious"
        if "reflected" in vt or "search" in vt or "반사" in ev or "마커" in ev:
            return "reflected"
        return "unknown"

    return "unknown"


def _fallback_sqli_type_confidence(evidence: str) -> tuple[str, str]:
    ev = evidence.lower()
    if "informational" in ev or "정보" in ev:
        return SQLI_INFORMATIONAL, LOW
    if "confirmed" in ev or "(confirmed)" in ev:
        return SQLI_CONFIRMED, HIGH
    if "candidate" in ev:
        return SQLI_CANDIDATE, LOW
    if "suspected" in ev:
        if any(x in ev for x in ("sqlstate", "mysql", "syntax", "db 에러", "db error")):
            return SQLI_SUSPECTED, HIGH
        return SQLI_SUSPECTED, MEDIUM
    if "error-based" in ev or "union-based" in ev:
        return SQLI_SUSPECTED, HIGH
    if "time-based" in ev:
        return SQLI_SUSPECTED, MEDIUM
    if any(x in ev for x in ("http 500", "http 302", "status", "length", "응답 길이")):
        return SQLI_CANDIDATE, LOW
    return SQLI_CANDIDATE, LOW


def _fallback_xss_type_confidence(evidence: str) -> tuple[str, str]:
    ev = evidence.lower()
    if "safe context" in ev or "safe_tag" in ev or "comment" in ev:
        return XSS_SUSPICIOUS, LOW
    if "stored" in ev:
        return XSS_STORED_REFLECTED, MEDIUM
    if "payload" in ev or "페이로드" in ev or "마커" in ev:
        return XSS_REFLECTED, MEDIUM
    return XSS_SUSPICIOUS, LOW


def _fallback_type_confidence(module: str, evidence: str) -> tuple[str, str]:
    if module == MODULE_SQLI:
        return _fallback_sqli_type_confidence(evidence)
    if module == MODULE_XSS:
        return _fallback_xss_type_confidence(evidence)
    if module == MODULE_BAC:
        return BAC_SUSPECTED_MEDIUM, MEDIUM
    return XSS_SUSPICIOUS, LOW


def _attach_common_fields(finding: dict, r: dict) -> dict:
    meta = r.get("meta") or {}
    finding["id"] = r.get("id")
    finding["point"] = r.get("point")
    finding["task_group_id"] = r.get("task_group_id")
    finding["inject_mode"] = r.get("inject_mode")
    finding["elapsed"] = r.get("elapsed") or 0.0
    finding["role"] = meta.get("role")
    return finding


def _make_finding(r: dict, evidence: str) -> dict:
    meta = r.get("meta") or {}
    vt = (meta.get("vuln_type") or "").lower()
    module = _derive_module(vt)
    category = _derive_category(module, vt, evidence)
    type_, confidence = _fallback_type_confidence(module, evidence)

    finding = make_finding(
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
    return _attach_common_fields(finding, r)


def _handle_xss(raw: tuple, r: dict, rid: str | None, findings: list[dict], found_ids: set) -> None:
    if rid in found_ids:
        return
    if not isinstance(raw, tuple) or not raw[0]:
        return

    if len(raw) >= 4:
        _found, evidence, xss_type, confidence = raw[:4]
    else:
        _found, evidence = raw[:2]
        xss_type, confidence = _fallback_xss_type_confidence(evidence)

    meta = r.get("meta") or {}
    vt = (meta.get("vuln_type") or "").lower()
    category = _derive_category(MODULE_XSS, vt, evidence)
    finding = make_finding(
        module=MODULE_XSS,
        type=xss_type,
        category=category,
        url=r.get("url") or "",
        param=r.get("inject_param"),
        payload=r.get("payload") or "",
        status=r.get("status"),
        confidence=confidence,
        evidence=evidence,
    )
    findings.append(_attach_common_fields(finding, r))
    if rid:
        found_ids.add(rid)


def _handle_sqli(raw, r: dict, rid: str | None, findings: list[dict], found_ids: set) -> None:
    if rid in found_ids:
        return
    if isinstance(raw, dict):
        finding = sqli_finding_from_verdict(raw)
        if finding:
            finding["id"] = raw.get("id")
            finding["task_group_id"] = raw.get("task_group_id")
            findings.append(finding)
            if rid:
                found_ids.add(rid)
        return
    if isinstance(raw, tuple) and raw[0]:
        findings.append(_make_finding(r, raw[1]))
        if rid:
            found_ids.add(rid)


def _handle_bac(raw: tuple, r: dict, rid: str | None, findings: list[dict], found_ids: set) -> None:
    if rid in found_ids:
        return
    if isinstance(raw, tuple) and raw[0]:
        findings.append(_make_finding(r, raw[1]))
        if rid:
            found_ids.add(rid)


def _handle_unknown(r: dict, findings: list[dict], found_ids: set) -> None:
    rid = r.get("id")
    raw_xss = validate_xss(r)
    if isinstance(raw_xss, tuple) and raw_xss[0]:
        _handle_xss(raw_xss, r, rid, findings, found_ids)
        return
    _handle_sqli(validate_sqli(r), r, rid, findings, found_ids)


def validate(results: list[dict], progress_callback=None) -> list[dict]:
    findings: list[dict] = []
    found_ids: set = set()
    total = len(results)

    for idx, r in enumerate(results):
        if progress_callback:
            progress_callback(idx + 1, total)
        if r.get("error") or not r.get("response_body"):
            continue

        vt = _vuln_type(r)
        if "sqli" in vt or "sql" in vt:
            _handle_sqli(validate_sqli(r), r, r.get("id"), findings, found_ids)
        elif "xss" in vt:
            _handle_xss(validate_xss(r), r, r.get("id"), findings, found_ids)
        elif "bac" in vt or "broken_access" in vt or "auth" in vt:
            _handle_bac(validate_bac(r), r, r.get("id"), findings, found_ids)
        else:
            _handle_unknown(r, findings, found_ids)

    for detector in [
        detect_error_group,
        detect_boolean_group,
        detect_time_group,
        detect_probe_group,
        detect_orderby_group,
        detect_bac_group,
    ]:
        for item in detector(results):
            if isinstance(item, dict) and "verdict" in item:
                _handle_sqli(item, item, item.get("id"), findings, found_ids)
                continue
            r = item["result"]
            evidence = item["evidence"]
            if r.get("id") in found_ids:
                continue
            findings.append(_make_finding(r, evidence))
            found_ids.add(r.get("id"))

    return findings


def run(
    input_file: str = "results/execution_results.json",
    output_file: str = "results/findings.json",
    progress_callback=None,
) -> list[dict]:
    results = load_json(input_file, [])
    findings = validate(results, progress_callback=progress_callback)
    save_json(output_file, findings)
    return findings
