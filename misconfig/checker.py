from __future__ import annotations

import re
import requests
import requests.exceptions
from typing import Optional

from findings import (
    misconfig_finding,
    append_findings,
    MISCONFIG_CONFIRMED,
    MISCONFIG_WARNING,
    HIGH,
    MEDIUM,
    LOW,
)

# ── 민감 파일 체크 대상 ────────────────────────────────────────
_SENSITIVE_FILES: list[tuple[str, str, str]] = [
    # 환경 변수
    ("/.env",                   "sensitive_file", "env_exposure"),
    ("/.env.local",             "sensitive_file", "env_exposure"),
    ("/.env.production",        "sensitive_file", "env_exposure"),
    ("/.env.backup",            "sensitive_file", "env_exposure"),
    # Git
    ("/.git/config",            "sensitive_file", "git_exposure"),
    # PHP 의존성 관리
    ("/composer.json",          "sensitive_file", "composer_exposure"),
    ("/composer.lock",          "sensitive_file", "composer_exposure"),
    # 접근 제어 파일
    ("/.htaccess",              "sensitive_file", "htaccess_exposure"),
    ("/.htpasswd",              "sensitive_file", "htpasswd_exposure"),
    # 설정 파일 (공통)
    ("/config.php",             "sensitive_file", "config_exposure"),
    ("/configuration.php",      "sensitive_file", "config_exposure"),
    ("/settings.php",           "sensitive_file", "config_exposure"),
    # 백업 파일 (그누보드)
    ("/config.php.bak",         "backup_file",    "backup_exposure"),
    ("/index.php.bak",          "backup_file",    "backup_exposure"),
    ("/db.php.bak",             "backup_file",    "backup_exposure"),
    # 백업 파일 (WordPress)
    ("/wp-config.php.bak",      "backup_file",    "backup_exposure"),
    ("/wp-config.php.old",      "backup_file",    "backup_exposure"),
    ("/wp-config.php~",         "backup_file",    "backup_exposure"),
    # phpinfo
    ("/phpinfo.php",            "phpinfo",        "phpinfo_exposure"),
    ("/info.php",               "phpinfo",        "phpinfo_exposure"),
    ("/test.php",               "phpinfo",        "phpinfo_exposure"),
    ("/php_info.php",           "phpinfo",        "phpinfo_exposure"),
    # 로그 파일
    ("/debug.log",              "log_file",       "log_exposure"),
    ("/error.log",              "log_file",       "log_exposure"),
    ("/php_errors.log",         "log_file",       "log_exposure"),
    ("/storage/logs/laravel.log", "log_file",     "log_exposure"),
    # DB 덤프
    ("/dump.sql",               "database_file",  "db_exposure"),
    ("/backup.sql",             "database_file",  "db_exposure"),
    ("/database.sql",           "database_file",  "db_exposure"),
    ("/db_backup.sql",          "database_file",  "db_exposure"),
]

# ── 디렉토리 리스팅 체크 대상 ─────────────────────────────────
_DIRECTORY_PATHS: list[str] = [
    # 그누보드
    "/data/",
    "/bbs/data/",
    "/bbs/upload/",
    "/theme/",
    # WordPress
    "/wp-content/uploads/",
    "/wp-content/",
    "/wp-includes/",
    # 공통
    "/uploads/",
    "/files/",
    "/backup/",
    "/static/",
    "/cache/",
    "/tmp/",
    "/logs/",
    "/log/",
    "/sql/",
    "/storage/",
]

# ── 판정 룰: 키워드 매치 기준 ─────────────────────────────────
_RULES: dict[str, dict] = {
    "env_exposure": {
        "keywords": [
            "DB_PASSWORD", "DATABASE_PASSWORD", "SECRET_KEY", "APP_SECRET",
            "APP_KEY", "DATABASE_URL", "DB_HOST", "API_KEY", "AWS_SECRET",
            "MAIL_PASSWORD", "REDIS_PASSWORD",
        ],
        "evidence_prefix": "sensitive env variable found",
    },
    "git_exposure": {
        "keywords": ["[core]", "repositoryformatversion", "[remote", "filemode ="],
        "evidence_prefix": "git config keyword found",
    },
    "composer_exposure": {
        "keywords": ['"require"', '"name"', '"version"', '"autoload"'],
        "evidence_prefix": "composer manifest exposed",
    },
    "htaccess_exposure": {
        "keywords": ["RewriteEngine", "AuthType", "AuthUserFile", "deny from", "Options -Indexes"],
        "evidence_prefix": ".htaccess file exposed",
    },
    "htpasswd_exposure": {
        "keywords": ["$apr1$", "$2y$", "$1$"],
        "evidence_prefix": ".htpasswd file exposed",
    },
    "config_exposure": {
        "keywords": [
            "DB_PASSWORD", "db_password", "database_password",
            "define('DB", 'define("DB', "mysqli_connect", "PDO::",
            "DB_HOST", "DB_USER",
        ],
        "evidence_prefix": "config file with credentials exposed",
    },
    "backup_exposure": {
        "keywords": [
            "<?php", "define(", "DB_PASSWORD", "DB_HOST", "DB_USER",
            "db_password", "mysql_connect", "PDO::", "secret_key",
        ],
        "evidence_prefix": "backup file contains sensitive content",
    },
    "phpinfo_exposure": {
        "keywords": ["PHP Version", "phpinfo()", "PHP Extension", "php.ini Path", "PHP Credits"],
        "evidence_prefix": "phpinfo page exposed",
    },
    "directory_listing": {
        "keywords": ["Index of /", "Directory listing for", "Parent Directory", "<title>Index of"],
        "evidence_prefix": "directory listing enabled",
    },
    "log_exposure": {
        "keywords": [
            "PHP Warning", "PHP Fatal", "PHP Notice", "SQL error",
            "Exception in", "Traceback", "Stack trace", "Error:",
        ],
        "evidence_prefix": "log file exposed",
    },
    "db_exposure": {
        "keywords": ["INSERT INTO", "CREATE TABLE", "DROP TABLE", "CHARSET=", "ENGINE=InnoDB"],
        "evidence_prefix": "database dump exposed",
    },
}

# ── 보안 헤더 ────────────────────────────────────────────────
_SECURITY_HEADERS: list[tuple[str, str]] = [
    ("X-Frame-Options",           "clickjacking_protection"),
    ("X-Content-Type-Options",    "mime_sniffing_protection"),
    ("Content-Security-Policy",   "csp"),
    ("Strict-Transport-Security", "hsts"),
    ("X-XSS-Protection",          "xss_header"),
    ("Referrer-Policy",           "referrer_policy"),
]

_VERSION_HEADERS: list[str] = [
    "Server",
    "X-Powered-By",
    "X-AspNet-Version",
    "X-Generator",
    "X-Drupal-Cache",
    "X-Runtime",
    "X-Backend-Server",
]

_ERROR_PATTERN = re.compile(
    r"(Fatal\s+error|Parse\s+error|SQL\s+syntax|mysql_fetch|mysqli_|"
    r"ORA-\d{5}|Microsoft\s+OLE\s+DB|ODBC\s+SQL|PostgreSQL.*ERROR|"
    r"Warning:\s+\w+\s*\(\)|Traceback\s+\(most\s+recent\s+call\s+last\))",
    re.IGNORECASE,
)

_REQUEST_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
}

_MIN_BODY_LEN = 100


# ── HTTP 헬퍼 ─────────────────────────────────────────────────

def _get(url: str, timeout: int = 10) -> Optional[requests.Response]:
    try:
        return requests.get(
            url, timeout=timeout, allow_redirects=False,
            headers=_REQUEST_HEADERS,
        )
    except requests.exceptions.Timeout:
        print(f"[MISCONFIG] timeout: {url}")
    except requests.exceptions.ConnectionError:
        print(f"[MISCONFIG] connection error: {url}")
    except requests.exceptions.RequestException as e:
        print(f"[MISCONFIG] request error ({type(e).__name__}): {url}")
    return None


def _head(url: str, timeout: int = 10) -> Optional[requests.Response]:
    try:
        return requests.head(
            url, timeout=timeout, allow_redirects=False,
            headers=_REQUEST_HEADERS,
        )
    except requests.exceptions.Timeout:
        print(f"[MISCONFIG] timeout (HEAD): {url}")
    except requests.exceptions.ConnectionError:
        print(f"[MISCONFIG] connection error (HEAD): {url}")
    except requests.exceptions.RequestException as e:
        print(f"[MISCONFIG] request error (HEAD) ({type(e).__name__}): {url}")
    return None


# ── 룰 매처 ──────────────────────────────────────────────────

def _match_keywords(body: str, rule_key: str) -> tuple[bool, str]:
    rule = _RULES.get(rule_key)
    if not rule:
        return False, ""
    bl = body.lower()
    for kw in rule["keywords"]:
        if kw.lower() in bl:
            return True, f"{rule['evidence_prefix']}: '{kw}'"
    return False, ""


# ── 체크 함수들 ───────────────────────────────────────────────

def _check_file(base_url: str, path: str, category: str, rule_key: str) -> list[dict]:
    url = base_url + path
    resp = _get(url)
    if resp is None:
        return []

    # 403: 파일이 존재하지만 접근 차단 — WARNING
    if resp.status_code == 403:
        print(f"[MISCONFIG] WARNING {category} (403 Forbidden): {url}")
        return [misconfig_finding(
            type=MISCONFIG_WARNING,
            category=category,
            url=url,
            status=403,
            confidence=LOW,
            evidence=f"{path} returned HTTP 403 — file may exist but access is restricted",
        )]

    if resp.status_code != 200:
        return []

    found, evidence = _match_keywords(resp.text, rule_key)
    if found:
        print(f"[MISCONFIG] CONFIRMED {category}: {url}")
        return [misconfig_finding(
            type=MISCONFIG_CONFIRMED,
            category=category,
            url=url,
            status=resp.status_code,
            confidence=HIGH,
            evidence=evidence,
        )]

    # 200이지만 키워드 없음 — 내용이 충분히 있을 때만 WARNING
    body_stripped = resp.text.strip()
    if len(body_stripped) > _MIN_BODY_LEN:
        print(f"[MISCONFIG] WARNING {category} (200, no keyword match): {url}")
        return [misconfig_finding(
            type=MISCONFIG_WARNING,
            category=category,
            url=url,
            status=resp.status_code,
            confidence=LOW,
            evidence=f"{path} returned HTTP 200 with {len(body_stripped)} bytes — manual review recommended",
        )]

    return []


def _check_dir(base_url: str, path: str) -> list[dict]:
    url = base_url + path
    resp = _get(url)
    if resp is None or resp.status_code != 200:
        return []

    found, evidence = _match_keywords(resp.text, "directory_listing")
    if found:
        print(f"[MISCONFIG] CONFIRMED directory_listing: {url}")
        return [misconfig_finding(
            type=MISCONFIG_CONFIRMED,
            category="directory_listing",
            url=url,
            status=resp.status_code,
            confidence=HIGH,
            evidence=evidence,
        )]
    return []


def _check_security_headers(base_url: str) -> list[dict]:
    findings = []
    home_url = base_url + "/"

    resp = _head(home_url)
    if resp is None:
        resp = _get(home_url)
    if resp is None:
        return findings

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    for header_name, category in _SECURITY_HEADERS:
        if header_name.lower() not in headers_lower:
            print(f"[MISCONFIG] WARNING missing_header: {header_name}")
            findings.append(misconfig_finding(
                type=MISCONFIG_WARNING,
                category="missing_security_header",
                url=home_url,
                status=resp.status_code,
                confidence=MEDIUM,
                evidence=f"security header not set: {header_name}",
                extra={"header": header_name, "category": category},
            ))

    for header_name in _VERSION_HEADERS:
        value = headers_lower.get(header_name.lower())
        if value:
            print(f"[MISCONFIG] WARNING version_disclosure: {header_name}: {value}")
            findings.append(misconfig_finding(
                type=MISCONFIG_WARNING,
                category="version_disclosure",
                url=home_url,
                status=resp.status_code,
                confidence=MEDIUM,
                evidence=f"version info exposed via header: {header_name}: {value}",
                extra={"header": header_name, "value": value},
            ))

    return findings


def _check_error_disclosure(base_url: str) -> list[dict]:
    findings = []
    home_url = base_url + "/"

    resp = _get(home_url)
    if resp is None or not resp.text:
        return findings

    m = _ERROR_PATTERN.search(resp.text)
    if m:
        print(f"[MISCONFIG] CONFIRMED error_disclosure: {m.group(0)[:60]}")
        findings.append(misconfig_finding(
            type=MISCONFIG_CONFIRMED,
            category="error_disclosure",
            url=home_url,
            status=resp.status_code,
            confidence=HIGH,
            evidence=f"error message in response: {m.group(0)[:100]}",
        ))

    return findings


# ── 메인 체크 함수 ────────────────────────────────────────────

def check(base_url: str, progress_callback=None) -> list[dict]:
    base_url = base_url.rstrip("/")
    findings: list[dict] = []

    total = len(_SENSITIVE_FILES) + len(_DIRECTORY_PATHS) + 2  # +2: headers, error
    done = 0

    def _tick():
        nonlocal done
        done += 1
        if progress_callback:
            progress_callback(done, total)

    print(f"[MISCONFIG] checking 민감 파일... ({len(_SENSITIVE_FILES)}개)")
    for path, category, rule_key in _SENSITIVE_FILES:
        findings.extend(_check_file(base_url, path, category, rule_key))
        _tick()

    print(f"[MISCONFIG] checking 디렉토리 리스팅... ({len(_DIRECTORY_PATHS)}개)")
    for path in _DIRECTORY_PATHS:
        findings.extend(_check_dir(base_url, path))
        _tick()

    print("[MISCONFIG] checking 보안 헤더...")
    findings.extend(_check_security_headers(base_url))
    _tick()

    print("[MISCONFIG] checking 에러 노출...")
    findings.extend(_check_error_disclosure(base_url))
    _tick()

    return findings


# ── run: 외부 진입점 ──────────────────────────────────────────

def run(
    base_url: str,
    output_file: str = "results/findings.json",
    progress_callback=None,
    append: bool = True,
) -> list[dict]:

    import json
    import os

    print(f"[MISCONFIG] start → {base_url}")
    findings = check(base_url, progress_callback=progress_callback)

    confirmed = sum(1 for f in findings if f.get("type") == MISCONFIG_CONFIRMED)
    warnings  = sum(1 for f in findings if f.get("type") == MISCONFIG_WARNING)
    print(f"[MISCONFIG] done: confirmed={confirmed}, warning={warnings}, total={len(findings)}")

    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)

    if append:
        append_findings(findings, output_file)
    else:
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(findings, f, ensure_ascii=False, indent=2)

    return findings


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8081"
    result = run(target, output_file="results/misconfig_findings.json", append=False)
    print(f"\n총 {len(result)}개 발견")
    for f in result:
        print(f"  [{f['type']:22s}] [{f['confidence']:6s}] {f['category']:25s} {f['url']}")
        print(f"    → {f['evidence']}")
