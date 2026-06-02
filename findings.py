from __future__ import annotations
from typing import Optional
import json
import os

# findings 저장 경로
FINDINGS_FILE = os.getenv("FINDINGS_FILE", "results/findings.json")

# ── type 상수 ──────────────────────────────────────────────
# SQLi
SQLI_CONFIRMED       = "SQLI_CONFIRMED"
SQLI_SUSPECTED       = "SQLI_SUSPECTED"
SQLI_CANDIDATE       = "SQLI_CANDIDATE"

# XSS
XSS_CONFIRMED        = "XSS_CONFIRMED"
XSS_STORED_CONFIRMED = "XSS_STORED_CONFIRMED"

# BAC
BAC_SUSPECTED_LOW    = "BAC_SUSPECTED_LOW"
BAC_SUSPECTED_MEDIUM = "BAC_SUSPECTED_MEDIUM"
BAC_SUSPECTED_HIGH   = "BAC_SUSPECTED_HIGH"
IDOR_SUSPECTED       = "IDOR_SUSPECTED"

# Misconfig
MISCONFIG_CONFIRMED  = "MISCONFIG_CONFIRMED"
MISCONFIG_WARNING    = "MISCONFIG_WARNING"

# ── confidence 상수 ────────────────────────────────────────
HIGH   = "high"
MEDIUM = "medium"
LOW    = "low"

# ── module 상수 ───────────────────────────────────────────
MODULE_SQLI     = "sqli"
MODULE_XSS      = "xss"
MODULE_BAC      = "bac"
MODULE_MISCONFIG = "misconfig"


# ── 판정 신호(verdict) 상수 ────────────────────────────────
# detector / validator 가 confidence 와 별개로 "확신 수준"을 표현하는 신호.
# 이 신호를 confidence(high/medium/low)로 매핑하는 단일 출처를 둔다.
VERDICT_CONFIRMED = "confirmed"
VERDICT_SUSPECTED = "suspected"
VERDICT_CANDIDATE = "candidate"

# verdict -> confidence 매핑 (보고서 양형의 단일 기준)
_VERDICT_TO_CONFIDENCE = {
    VERDICT_CONFIRMED: HIGH,
    VERDICT_SUSPECTED: MEDIUM,
    VERDICT_CANDIDATE: LOW,
}


def verdict_to_confidence(verdict: str) -> str:
    """판정 신호를 confidence 등급으로 변환. 알 수 없으면 LOW로 보수 처리."""
    return _VERDICT_TO_CONFIDENCE.get((verdict or "").lower(), LOW)


def make_finding(
    module:     str,
    type:       str,
    category:   str,
    url:        str,
    confidence: str,
    evidence:   str,
    param:      Optional[str] = None,
    payload:    Optional[str] = None,
    status:     Optional[int] = None,
    extra:      Optional[dict] = None,
) -> dict:

    finding = {
        "module":     module,
        "type":       type,
        "category":   category,
        "url":        url,
        "param":      param,
        "payload":    payload,
        "status":     status,
        "confidence": confidence,
        "evidence":   evidence,
    }
    if extra:
        finding["extra"] = extra
    return finding


# ── 모듈별 헬퍼 ───────────────────────────────────────────

def sqli_finding(
    category:  str,
    url:       str,
    param:     str,
    payload:   str,
    status:    int,
    evidence:  str,
    confidence: str = HIGH,
    type:      str = SQLI_CONFIRMED,
) -> dict:
    """SQLi finding 생성 헬퍼"""
    return make_finding(
        module=MODULE_SQLI,
        type=type,
        category=category,
        url=url,
        param=param,
        payload=payload,
        status=status,
        confidence=confidence,
        evidence=evidence,
    )


def xss_finding(
    category:  str,
    url:       str,
    param:     str,
    payload:   str,
    status:    int,
    evidence:  str,
    confidence: str = HIGH,
    type:      str = XSS_CONFIRMED,
) -> dict:
    """XSS finding 생성 헬퍼"""
    return make_finding(
        module=MODULE_XSS,
        type=type,
        category=category,
        url=url,
        param=param,
        payload=payload,
        status=status,
        confidence=confidence,
        evidence=evidence,
    )


def bac_finding(
    type:      str,
    category:  str,
    url:       str,
    status:    int,
    evidence:  str,
    confidence: str,
    param:     Optional[str] = None,
    extra:     Optional[dict] = None,
) -> dict:
    """BAC finding 생성 헬퍼"""
    return make_finding(
        module=MODULE_BAC,
        type=type,
        category=category,
        url=url,
        param=param,
        payload=None,
        status=status,
        confidence=confidence,
        evidence=evidence,
        extra=extra,
    )


def misconfig_finding(
    type:      str,
    category:  str,
    url:       str,
    status:    int,
    evidence:  str,
    confidence: str = HIGH,
    extra:     Optional[dict] = None,
) -> dict:
    """Misconfig finding 생성 헬퍼"""
    return make_finding(
        module=MODULE_MISCONFIG,
        type=type,
        category=category,
        url=url,
        param=None,
        payload=None,
        status=status,
        confidence=confidence,
        evidence=evidence,
        extra=extra,
    )


# ── 저장/로드 ─────────────────────────────────────────────

def save_findings(findings: list[dict], path: str = FINDINGS_FILE) -> None:
    """findings 리스트를 JSON 파일로 저장"""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(findings, f, ensure_ascii=False, indent=2)


def load_findings(path: str = FINDINGS_FILE) -> list[dict]:
    """findings JSON 파일 로드. 없으면 빈 리스트 반환"""
    if not os.path.exists(path):
        return []
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def append_findings(new_findings: list[dict], path: str = FINDINGS_FILE) -> None:
    """기존 findings에 새 결과를 추가하고 저장"""
    existing = load_findings(path)
    existing.extend(new_findings)
    save_findings(existing, path)


# ── 사용 예시 ─────────────────────────────────────────────
if __name__ == "__main__":
    examples = [
        sqli_finding(
            category="error_based",
            url="/bbs/search.php",
            param="stx",
            payload="a'))))AND(EXTRACTVALUE(1,CONCAT(0x7e,database())))#",
            status=200,
            evidence="xpath syntax error found in response",
        ),
        xss_finding(
            category="reflected",
            url="/bbs/search.php",
            param="stx",
            payload='" onmouseover=alert(1) x="',
            status=200,
            evidence="onmouseover=alert found unencoded in response",
        ),
        bac_finding(
            type=BAC_SUSPECTED_MEDIUM,
            category="admin_area",
            url="/adm/",
            status=200,
            confidence=MEDIUM,
            evidence="user session accessed admin-like path without login/denied response",
            extra={"role": "user", "session": "user"},
        ),
        misconfig_finding(
            type=MISCONFIG_CONFIRMED,
            category="git_exposure",
            url="/.git/config",
            status=200,
            evidence="response contains [core] and repositoryformatversion",
        ),
    ]

    for f in examples:
        print(json.dumps(f, ensure_ascii=False, indent=2))