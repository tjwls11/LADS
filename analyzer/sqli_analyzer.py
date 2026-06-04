from __future__ import annotations

import re
from collections import defaultdict
from typing import Optional

SLEEP_THRESHOLD       = 4.5
BOOL_SIGNAL_MIN       = 0.05
BOOL_GROUP_THRESHOLD  = 0.05
ORDERBY_DIFF_THRES    = 0.10


DB_ERROR_KEYWORDS = (
    "you have an error in your sql syntax",
    "check the manual that corresponds to your mysql server version",
    "check the manual that fits your mysql server version",
    "warning: mysql",
    "warning: mysqli",
    "mysqlsyntaxerrorexception",
    "valid mysql result",
    "supplied argument is not a valid mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql_query",
    "mysqli_",
    "pdoexception",
    "pdo_mysql",
    "pdo/mysql",
    "sqlstate",
    "unknown column",
    "duplicate entry",
    "division by zero",
    "column count doesn't match",
    "the used select statements have a different number",
)

_BOOL_TRUE = re.compile(
    r"1\s*=\s*1"
    r"|'\s*([a-z0-9])\s*'\s*=\s*'\s*\1"
    r"|\bor\s+1\b"
    r"|\band\s+1\s*=\s*1"
    r"|\btrue\b"
    r"|length\(.+\)\s*>\s*0"
    r"|exists\s*\("
    r"|case\s+when\s*\(\s*1\s*=\s*1",
    re.IGNORECASE,
)
_BOOL_FALSE = re.compile(
    r"1\s*=\s*2"
    r"|1\s*=\s*0"
    r"|\band\s+1\s*=\s*2"
    r"|\bfalse\b"
    r"|\band\s+0\b"
    r"|case\s+when\s*\(\s*1\s*=\s*2",
    re.IGNORECASE,
)

_BOOL_PROBE = re.compile(
    r"ascii\(.+\)\s*[=><]"
    r"|(?:substr|substring|mid)\([^)]+\)\s*[=><]"
    r"|length\(.+\)\s*=\s*\d+"
    r"|.+\s+regexp\s+",
    re.IGNORECASE,
)

_ORDERBY_INJECT = re.compile(r"order\s+by\s+(?:\d+|\(|\w+\s*,)", re.IGNORECASE)
_ORDERBY_NUM = re.compile(r"order\s+by\s+(\d+)", re.IGNORECASE)


def _is_group_candidate(payload: str) -> bool:
    if not payload:
        return False
    if _BOOL_TRUE.search(payload):
        return True
    if _BOOL_FALSE.search(payload):
        return True
    if _BOOL_PROBE.search(payload):
        return True
    if _ORDERBY_INJECT.search(payload):
        return True
    return False


def _extract_response(test_result: dict) -> dict:
    if "response" in test_result and isinstance(test_result["response"], dict):
        r = test_result["response"]
        return {
            "body":    (r.get("body") or "").lower(),
            "elapsed": float(r.get("elapsed") or 0.0),
            "length":  int(r.get("length") or 0),
            "status":  r.get("status"),
        }
    body = test_result.get("response_body") or ""
    return {
        "body":    body.lower(),
        "elapsed": float(test_result.get("elapsed") or 0.0),
        "length":  int(test_result.get("length") or 0),
        "status":  test_result.get("status"),
    }


def _vuln_type(r: dict) -> str:
    return ((r.get("meta") or {}).get("vuln_type") or "").lower()


# task_group_id가 있으면 우선 사용하고 없으면 기존 묶음 키를 반환
def _group_key(r: dict, fallback_category: str) -> tuple | str:
    return r.get("task_group_id") or (
        r.get("url"),
        r.get("inject_param"),
        fallback_category,
    )


# 응답 시간을 밀리초 단위로 반환
def _elapsed_ms(r: dict) -> int:
    elapsed = float(r.get("elapsed") or 0.0)
    return int(round(elapsed * 1000))


# 요청 결과의 역할명을 반환 
# 예: "attack", "baseline", "control" 등, meta.role이 없으면 "attack"으로 기본값 사용
def _result_role(r: dict, default: str = "attack") -> str:
    meta = r.get("meta") or {}
    return meta.get("role") or default


# 단일 요청 결과를 evidence.requests 항목으로 변환하여 반환
def _request_evidence(r: dict, default_role: str = "attack") -> dict:
    return {
        "role": _result_role(r, default_role),
        "value": r.get("base_value"),
        "payload": r.get("payload"),
        "status": r.get("status"),
        "length": r.get("length") if r.get("length") is not None else _body_length(r),
        "elapsed_ms": _elapsed_ms(r),
    }


# 그룹의 요청 결과들을 evidence.requests 목록으로 반환
def _requests_evidence(group: list[dict], default_role: str = "attack") -> list[dict]:
    return [_request_evidence(r, default_role) for r in group]


# evidence.target 영역을 생성하여 반환
def _target_evidence(r: dict) -> dict:
    return {
        "url": r.get("url") or "",
        "method": r.get("method") or "GET",
        "param": r.get("inject_param"),
        "inject_mode": r.get("inject_mode") or "replace",
    }


# detector 판정 결과 구조를 생성하여 반환
def _build_decision(
    result: dict,
    group: list[dict],
    category: str,
    verdict: str,
    confidence: str,
    reason: str,
    title: str | None = None,
    extra_evidence: dict | None = None,
) -> dict:
    evidence = {
        "target": _target_evidence(result),
        "requests": _requests_evidence(group),
    }
    if extra_evidence:
        evidence.update(extra_evidence)

    return {
        "id": result.get("id"),
        "task_group_id": result.get("task_group_id"),
        "category": category,
        "verdict": verdict,
        "confidence": confidence,
        "title": title or f"SQLi {category} {verdict}",
        "reason": reason,
        "evidence": evidence,
    }


def _body_length(r: dict) -> int:
    body = r.get("response_body") or ""
    return len(body)


def _has_db_error(body: str) -> bool:
    if not body:
        return False
    return any(sig in body for sig in DB_ERROR_KEYWORDS)


# TODO: extractvalue/updatexml 등 페이로드 반사는 DB 에러가 아닌 별도 evidence로 분리할 필요 있음
# 응답 본문에서 발견된 DB 에러 목록을 반환
def _matched_db_errors(body: str) -> list[str]:
    if not body:
        return []
    return [sig for sig in DB_ERROR_KEYWORDS if sig in body]


# 그룹 전체에서 발견된 DB 에러 목록을 반환
def _group_matched_db_errors(group: list[dict]) -> list[str]:
    matched: list[str] = []
    for r in group:
        body = (r.get("response_body") or "").lower()
        for sig in _matched_db_errors(body):
            if sig not in matched:
                matched.append(sig)
    return matched


def _check_time_based(elapsed: float) -> Optional[str]:
    if elapsed >= SLEEP_THRESHOLD:
        return f"Time-based SQLi (응답 지연 {elapsed:.2f}s >= {SLEEP_THRESHOLD}s)"
    return None


def _check_error_based(body: str) -> Optional[str]:
    for sig in DB_ERROR_KEYWORDS:
        if sig in body:
            return f"Error-based SQLi (DB 에러 노출: '{sig}')"
    return None


def validate_sqli(test_result: dict) -> tuple[bool, str]:
    if not test_result:
        return False, "검증 불가 (입력 없음)"

    resp = _extract_response(test_result)
    if not resp["body"] and resp["elapsed"] == 0.0:
        return False, "검증 불가 (응답 데이터 누락)"

    msg = _check_time_based(resp["elapsed"])
    if msg:
        return True, msg

    payload = test_result.get("payload") or ""
    if _is_group_candidate(payload):
        return False, "그룹 분석 대상 (Phase 2로 위임)"

    msg = _check_error_based(resp["body"])
    if msg:
        return True, msg

    return False, "안전함 (SQLi 시그니처 미검출)"


# SQLi 결과만 필터링하여 반환
def _sqli_response_results(results: list[dict]) -> list[dict]:
    return [
        r for r in results
        if not r.get("error")
        and r.get("response_body")
        and ("sqli" in _vuln_type(r) or "sql" in _vuln_type(r))
    ]


# 응답 길이 차이 비율을 계산하여 반환
def _length_diff_score(group: list[dict]) -> float:
    lengths = [_body_length(r) for r in group]
    if len(lengths) < 2:
        return 0.0
    min_len, max_len = min(lengths), max(lengths)
    return (max_len - min_len) / max(max_len, 1)


# error-based SQLi 그룹 판정 결과를 반환
def detect_error_group(results: list[dict]) -> list[dict]:
    sqli_results = _sqli_response_results(results)
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in sqli_results:
        key = _group_key(r, "error")
        groups[key].append(r)

    detected: list[dict] = []

    for _key, group in groups.items():
        matched_errors = _group_matched_db_errors(group)
        error_counts = {
            sig: sum(1 for r in group if sig in (r.get("response_body") or "").lower())
            for sig in matched_errors
        }
        repeated_errors = [sig for sig, count in error_counts.items() if count >= 2]
        statuses = {r.get("status") for r in group if r.get("status") is not None}
        has_status_signal = any(status in (302, 500) for status in statuses)
        has_status_change = len(statuses) >= 2
        diff = _length_diff_score(group)

        if repeated_errors:
            verdict = "confirmed"
            confidence = "high"
            evidence = (
                f"Error-based SQLi confirmed: 동일 DB 에러 {len(repeated_errors)}개가 "
                f"2회 이상 재현됨"
            )
        elif matched_errors:
            verdict = "suspected"
            confidence = "high"
            evidence = (
                f"Error-based SQLi suspected: 공격 응답에서 DB 에러 시그니처 발견 "
                f"({', '.join(matched_errors)})"
            )
        elif has_status_signal or has_status_change or diff >= BOOL_GROUP_THRESHOLD:
            verdict = "candidate"
            confidence = "low"
            evidence = (
                f"Error-based SQLi candidate: status={sorted(statuses)}, "
                f"diff={diff:.1%}, DB 에러 시그니처 없음"
            )
        else:
            verdict = "informational"
            confidence = "low"
            evidence = "Error-based SQLi informational: 의미 있는 응답 차이 없음"

        best = max(group, key=lambda r: (len(_matched_db_errors((r.get("response_body") or "").lower())), _body_length(r)))
        decision = _build_decision(
            result=best,
            group=group,
            category="error",
            verdict=verdict,
            confidence=confidence,
            title=f"SQLi error-based {verdict}",
            reason=evidence,
            extra_evidence={
                "matched_errors": matched_errors,
                "repeated_errors": repeated_errors,
                "diff_score": round(diff, 4),
                "statuses": sorted(statuses),
            },
        )
        detected.append(decision)

    return detected


# time-based SQLi 그룹 판정 결과를 반환
def detect_time_group(results: list[dict]) -> list[dict]:
    sqli_results = _sqli_response_results(results)
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in sqli_results:
        key = _group_key(r, "time")
        groups[key].append(r)

    detected: list[dict] = []

    for _key, group in groups.items():
        delay_items = [
            r for r in group
            if _result_role(r) == "delay_attack"
            or "sleep" in (r.get("payload") or "").lower()
            or "benchmark" in (r.get("payload") or "").lower()
            or float(r.get("elapsed") or 0.0) >= SLEEP_THRESHOLD
        ]
        if not delay_items:
            continue

        slow_count = sum(1 for r in delay_items if float(r.get("elapsed") or 0.0) >= SLEEP_THRESHOLD)
        slow_ratio = slow_count / max(len(delay_items), 1)
        avg_delay = sum(float(r.get("elapsed") or 0.0) for r in delay_items) / len(delay_items)

        if len(delay_items) >= 2 and slow_ratio >= 0.9:
            verdict = "confirmed"
            confidence = "high"
            evidence = (
                f"Time-based SQLi confirmed: delay payload {len(delay_items)}개 중 "
                f"{slow_count}개가 {SLEEP_THRESHOLD}s 이상 지연됨"
            )
        elif len(delay_items) >= 2 and slow_count:
            verdict = "suspected"
            confidence = "medium"
            evidence = (
                f"Time-based SQLi suspected: delay payload 평균 응답 시간 "
                f"{avg_delay:.2f}s, 재현율 {slow_ratio:.0%}"
            )
        elif slow_count:
            verdict = "candidate"
            confidence = "low"
            evidence = (
                f"Time-based SQLi candidate: 단일 delay payload에서 "
                f"{avg_delay:.2f}s 지연 발생"
            )
        else:
            verdict = "informational"
            confidence = "low"
            evidence = "Time-based SQLi informational: 의미 있는 지연 없음"

        best = max(delay_items, key=lambda r: float(r.get("elapsed") or 0.0))
        decision = _build_decision(
            result=best,
            group=group,
            category="time",
            verdict=verdict,
            confidence=confidence,
            title=f"SQLi time-based {verdict}",
            reason=evidence,
            extra_evidence={
                "matched_errors": _group_matched_db_errors(group),
                "diff_score": None,
                "delay_threshold": SLEEP_THRESHOLD,
                "slow_ratio": round(slow_ratio, 4),
                "avg_delay": round(avg_delay, 4),
            },
        )
        detected.append(decision)

    return detected


def detect_boolean_group(results: list[dict]) -> list[dict]:
    sqli_results = [
        r for r in results
        if not r.get("error")
        and r.get("response_body")
        and ("sqli" in _vuln_type(r) or "sql" in _vuln_type(r))
    ]

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in sqli_results:
        key = _group_key(r, "boolean")
        groups[key].append(r)

    detected: list[dict] = []

    for _key, group in groups.items():
        true_items, false_items = [], []
        for r in group:
            payload = r.get("payload") or ""
            if _BOOL_TRUE.search(payload):
                true_items.append(r)
            if _BOOL_FALSE.search(payload):
                false_items.append(r)

        if true_items and false_items:
            avg_true  = sum(_body_length(r) for r in true_items)  / len(true_items)
            avg_false = sum(_body_length(r) for r in false_items) / len(false_items)
            max_len   = max(avg_true, avg_false, 1)
            diff      = abs(avg_true - avg_false) / max_len

            if diff >= BOOL_GROUP_THRESHOLD:
                direction = "true>false" if avg_true > avg_false else "true<false"
                evidence = (
                    f"Boolean-based SQLi signal: "
                    f"true_len={avg_true:.0f}, false_len={avg_false:.0f}, "
                    f"diff={diff:.1%} ({direction})"
                )
                best = max(true_items, key=_body_length)
                matched_errors = _group_matched_db_errors(true_items + false_items)
                has_repeated_pair = len(true_items) >= 2 and len(false_items) >= 2
                decision = _build_decision(
                    result=best,
                    group=group,
                    category="boolean",
                    verdict="suspected" if matched_errors or has_repeated_pair else "candidate",
                    confidence="high" if matched_errors else ("medium" if has_repeated_pair else "low"),
                    reason=evidence,
                    extra_evidence={
                        "matched_errors": matched_errors,
                        "diff_score": round(diff, 4),
                        "repeated_pair": has_repeated_pair,
                    },
                )
                detected.append(decision)
                continue


            # TODO: 문제있는 부분 (아래) 수정해야함
            sample_body = (true_items[0].get("response_body") or "").lower()
            if _has_db_error(sample_body):
                evidence = (
                    f"Boolean-based SQLi (suspected): "
                    f"true {len(true_items)}개 / false {len(false_items)}개 시도, "
                    f"응답 크기 동일 (diff={diff:.1%}) + DB 에러 시그니처 동반 → "
                    f"CMS 동일 에러 페이지 환경"
                )
            else:
                evidence = (
                    f"Boolean SQLi candidate: "
                    f"true {len(true_items)}개 / false {len(false_items)}개 시도, "
                    f"응답 동일 (diff={diff:.1%}), 수동 확인 필요"
                )
            best = true_items[0]
            matched_errors = _group_matched_db_errors(true_items + false_items)
            decision = _build_decision(
                result=best,
                group=group,
                category="boolean",
                verdict="suspected" if matched_errors else "informational",
                confidence="high" if matched_errors else "low",
                reason=evidence,
                extra_evidence={
                    "matched_errors": matched_errors,
                    "diff_score": round(diff, 4),
                },
            )
            detected.append(decision)
            continue

        candidate_items = true_items or false_items
        if candidate_items:
            kind = "TRUE" if true_items else "FALSE"
            sample_body = (candidate_items[0].get("response_body") or "").lower()
            error_note = " + DB 에러 동반" if _has_db_error(sample_body) else ""
            evidence = (
                f"Boolean SQLi candidate ({kind} only): "
                f"{len(candidate_items)}개 페이로드 시도, "
                f"짝 페이로드 부재로 응답 비교 불가{error_note}"
            )
            best = candidate_items[0]
            matched_errors = _group_matched_db_errors(candidate_items)
            decision = _build_decision(
                result=best,
                group=group,
                category="boolean",
                verdict="suspected" if matched_errors else "candidate",
                confidence="high" if matched_errors else "low",
                reason=evidence,
                extra_evidence={
                    "matched_errors": matched_errors,
                    "diff_score": None,
                },
            )
            detected.append(decision)

    return detected


def detect_probe_group(results: list[dict]) -> list[dict]:
    """ASCII/SUBSTRING/MID/REGEXP/LENGTH=N 등 정찰 페이로드 전용."""
    probe_results = [
        r for r in results
        if not r.get("error")
        and r.get("response_body")
        and ("sqli" in _vuln_type(r) or "sql" in _vuln_type(r))
        and _BOOL_PROBE.search(r.get("payload") or "")
    ]

    if not probe_results:
        return []

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in probe_results:
        key = _group_key(r, "boolean")
        groups[key].append(r)

    detected: list[dict] = []

    for _key, group in groups.items():
        lengths = [_body_length(r) for r in group]
        if not lengths:
            continue

        min_len, max_len_v = min(lengths), max(lengths)
        diff = (max_len_v - min_len) / max(max_len_v, 1)

        sample_body = (group[0].get("response_body") or "").lower()
        matched_errors = _group_matched_db_errors(group)
        has_error = _has_db_error(sample_body)

        if diff >= BOOL_GROUP_THRESHOLD and len(group) >= 2:
            evidence = (
                f"Boolean Probe SQLi (confirmed): {len(group)}개 정찰 페이로드 응답 분산 "
                f"(min={min_len}b, max={max_len_v}b, diff={diff:.1%})"
            )
        elif has_error:
            evidence = (
                f"Boolean Probe SQLi (suspected): {len(group)}개 정찰 페이로드 시도, "
                f"응답 동일하지만 DB 에러 시그니처 동반"
            )
        else:
            evidence = (
                f"Boolean Probe SQLi candidate: {len(group)}개 정찰 페이로드 시도 "
                f"(ASCII/SUBSTRING/MID/REGEXP 등), 응답 차이 없음"
            )

        best = max(group, key=_body_length)
        if matched_errors:
            verdict = "suspected"
            confidence = "high"
        elif diff >= BOOL_GROUP_THRESHOLD and len(group) >= 2:
            verdict = "suspected"
            confidence = "medium"
        elif len(group) < 2:
            verdict = "candidate"
            confidence = "low"
        else:
            verdict = "informational"
            confidence = "low"
        decision = _build_decision(
            result=best,
            group=group,
            category="boolean",
            verdict=verdict,
            confidence=confidence,
            reason=evidence,
            extra_evidence={
                "matched_errors": matched_errors,
                "diff_score": round(diff, 4),
            },
        )
        detected.append(decision)

    return detected


def detect_orderby_group(results: list[dict]) -> list[dict]:
    orderby_results = [
        r for r in results
        if not r.get("error")
        and r.get("response_body")
        and _ORDERBY_INJECT.search(r.get("payload") or "")
    ]

    if not orderby_results:
        return []

    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in orderby_results:
        key = _group_key(r, "order_by")
        groups[key].append(r)

    detected: list[dict] = []

    for _key, group in groups.items():
        if len(group) < 2:
            if group:
                sample_body = (group[0].get("response_body") or "").lower()
                error_note = " + DB 에러 동반" if _has_db_error(sample_body) else ""
                evidence = (
                    f"ORDER BY SQLi candidate: 단일 페이로드 시도, "
                    f"비교용 baseline 부족{error_note}"
                )
                matched_errors = _group_matched_db_errors(group)
                decision = _build_decision(
                    result=group[0],
                    group=group,
                    category="order_by",
                    verdict="suspected" if matched_errors else "candidate",
                    confidence="high" if matched_errors else "low",
                    reason=evidence,
                    extra_evidence={
                        "matched_errors": matched_errors,
                        "diff_score": None,
                    },
                )
                detected.append(decision)
            continue

        lengths = [_body_length(r) for r in group]
        min_len, max_len_v = min(lengths), max(lengths)
        if max_len_v == 0:
            continue

        diff = (max_len_v - min_len) / max_len_v

        has_error = any(
            "unknown column" in (r.get("response_body") or "").lower()
            for r in group
        )

        if diff >= ORDERBY_DIFF_THRES or has_error:
            evidence_extra = " + 'unknown column' 에러" if has_error else ""
            evidence = (
                f"ORDER BY SQLi (confirmed): {len(group)}개 페이로드 응답 분산 "
                f"(min={min_len}b, max={max_len_v}b, diff={diff:.1%}){evidence_extra}"
            )
            best = max(group, key=_body_length)
            matched_errors = _group_matched_db_errors(group)
            if has_error and "unknown column" not in matched_errors:
                matched_errors.append("unknown column")
            decision = _build_decision(
                result=best,
                group=group,
                category="order_by",
                verdict="suspected",
                confidence="high" if matched_errors else "medium",
                reason=evidence,
                extra_evidence={
                    "matched_errors": matched_errors,
                    "diff_score": round(diff, 4),
                },
            )
            detected.append(decision)
        else:
            sample_body = (group[0].get("response_body") or "").lower()
            db_note = " + DB 에러 동반" if _has_db_error(sample_body) else ""
            evidence = (
                f"ORDER BY SQLi candidate: {len(group)}개 페이로드 시도, "
                f"응답 동일 (diff={diff:.1%}){db_note}"
            )
            best = group[0]
            matched_errors = _group_matched_db_errors(group)
            decision = _build_decision(
                result=best,
                group=group,
                category="order_by",
                verdict="suspected" if matched_errors else "informational",
                confidence="high" if matched_errors else "low",
                reason=evidence,
                extra_evidence={
                    "matched_errors": matched_errors,
                    "diff_score": round(diff, 4),
                },
            )
            detected.append(decision)

    return detected
