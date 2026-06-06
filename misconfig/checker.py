from __future__ import annotations

import os
import sys
import re
import time
import requests
import requests.exceptions
from typing import Optional
from utilities import normalize_base_url, save_json

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

# ── 보안 헤더: (헤더명, category, finding_type, confidence) ─────
# OWASP Secure Headers / MDN 기준 가중치 적용
_SECURITY_HEADERS: list[tuple[str, str, str, str]] = [
    ("Content-Security-Policy",   "csp",                     MISCONFIG_CONFIRMED, HIGH),
    ("Strict-Transport-Security", "hsts",                     MISCONFIG_CONFIRMED, HIGH),
    ("X-Frame-Options",           "clickjacking_protection",  MISCONFIG_WARNING,   MEDIUM),
    ("X-Content-Type-Options",    "mime_sniffing_protection",  MISCONFIG_WARNING,   MEDIUM),
    ("Referrer-Policy",           "referrer_policy",           MISCONFIG_WARNING,   LOW),
    ("X-XSS-Protection",          "xss_header",                MISCONFIG_WARNING,   LOW),
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

# ── NVD API ──────────────────────────────────────────────────────
_NVD_API_URL          = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_NVD_RESULTS_PER_PAGE = 5
_NVD_RATE_LIMIT_DELAY = 6.5  # API 키 없을 때: 30초에 5회 제한

_CPE_VENDOR_MAP: dict[str, tuple[str, str]] = {
    "apache":    ("apache",    "http_server"),
    "nginx":     ("nginx",     "nginx"),
    "php":       ("php",       "php"),
    "openssl":   ("openssl",   "openssl"),
    "iis":       ("microsoft", "internet_information_services"),
    "tomcat":    ("apache",    "tomcat"),
    "lighttpd":  ("lighttpd",  "lighttpd"),
    "drupal":    ("drupal",    "drupal"),
    "wordpress": ("wordpress", "wordpress"),
}

_HEADER_VERSION_RE = re.compile(
    r"([\w][\w\-]*)[/ ]([\d]+\.[\d]+(?:\.[\d]+){0,2})",
    re.IGNORECASE,
)

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

_LOGIN_PAGE_RE = re.compile(
    r'input[^>]+type=["\']password["\']'
    r'|name=["\'](?:password|passwd|pw|user_pw)["\']',
    re.IGNORECASE,
)


def _is_login_page(body: str) -> bool:
    return bool(_LOGIN_PAGE_RE.search(body))


# ── HTTP 헬퍼 ─────────────────────────────────────────────────

def _get(url: str, timeout: int = 10, follow: bool = False) -> Optional[requests.Response]:
    try:
        return requests.get(
            url, timeout=timeout, allow_redirects=follow,
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


# ── NVD 헬퍼 ─────────────────────────────────────────────────────

def _parse_product_version(header_value: str) -> tuple[str, str, str] | None:
    """
    헤더 값 → CPE 조회용 (vendor, product, version).
    예: "Apache/2.4.54" → ("apache", "http_server", "2.4.54")
    매핑 불가 제품은 None 반환.
    """
    m = _HEADER_VERSION_RE.search(header_value)
    if not m:
        return None
    product_raw = m.group(1).lower()
    version     = m.group(2)
    for key, (vendor, product) in _CPE_VENDOR_MAP.items():
        if key in product_raw:
            return vendor, product, version
    return None


def _ver(s: str) -> tuple[int, ...]:
    """버전 문자열을 정수 튜플로 변환 (비교용)."""
    try:
        return tuple(int(x) for x in re.split(r"[.\-]", s)[:3])
    except Exception:
        return (0, 0, 0)


def _cve_affects_version(version: str, configurations: list) -> bool:
    """NVD configurations 에서 version 범위 체크. 하나라도 해당하면 True."""
    v = _ver(version)
    for node_group in configurations:
        for node in node_group.get("nodes", []):
            for match in node.get("cpeMatch", []):
                if not match.get("vulnerable"):
                    continue
                vsi = match.get("versionStartIncluding")
                vse = match.get("versionStartExcluding")
                vei = match.get("versionEndIncluding")
                vee = match.get("versionEndExcluding")

                # 버전 범위 없음 → criteria 의 특정 버전 or 와일드카드
                if not any([vsi, vse, vei, vee]):
                    criteria = match.get("criteria", "")
                    parts = criteria.split(":")
                    cpe_ver = parts[5] if len(parts) > 5 else "*"
                    if cpe_ver == "*" or _ver(cpe_ver) == v:
                        return True
                    continue

                # start 체크
                if vsi and v < _ver(vsi):
                    continue
                if vse and v < _ver(vse):
                    pass  # versionStartExcluding: v >= vse 이면 통과
                elif vse and v <= _ver(vse):
                    continue

                # end 체크
                if vei and v > _ver(vei):
                    continue
                if vee and v >= _ver(vee):
                    continue

                return True
    return False


def _query_nvd_cves(vendor: str, product: str, version: str) -> list[dict]:
    """
    NVD API v2 — CPE 기반 CVE 조회 + 버전 범위 필터링.
    환경변수 NVD_API_KEY 있으면 rate limit 완화 (50req/30s).
    """
    cpe_name = f"cpe:2.3:a:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
    params   = {"cpeName": cpe_name, "resultsPerPage": _NVD_RESULTS_PER_PAGE}
    headers  = {}
    api_key  = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key

    try:
        resp = requests.get(_NVD_API_URL, params=params, headers=headers, timeout=15)
        if resp.status_code != 200:
            print(f"[MISCONFIG] NVD API {resp.status_code}: {cpe_name}")
            return []
        data = resp.json()
    except Exception as e:
        print(f"[MISCONFIG] NVD API error ({type(e).__name__}): {e}")
        return []

    results = []
    for item in data.get("vulnerabilities", []):
        cve      = item.get("cve", {})
        cve_id   = cve.get("id", "")
        metrics  = cve.get("metrics", {})

        cvss31 = metrics.get("cvssMetricV31") or []
        cvss30 = metrics.get("cvssMetricV30") or []
        cvss2  = metrics.get("cvssMetricV2")  or []

        score    = None
        severity = "UNKNOWN"
        if cvss31:
            score    = cvss31[0].get("cvssData", {}).get("baseScore")
            severity = cvss31[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
        elif cvss30:
            score    = cvss30[0].get("cvssData", {}).get("baseScore")
            severity = cvss30[0].get("cvssData", {}).get("baseSeverity", "UNKNOWN")
        elif cvss2:
            score    = cvss2[0].get("cvssData", {}).get("baseScore")
            severity = cvss2[0].get("baseSeverity", "UNKNOWN")

        descriptions = cve.get("descriptions", [])
        desc = next((d["value"] for d in descriptions if d.get("lang") == "en"), "")
        configurations = cve.get("configurations", [])

        # 버전 범위 필터링: 이 버전에 실제로 해당하는 CVE만 포함
        if configurations and not _cve_affects_version(version, configurations):
            print(f"[MISCONFIG] CVE {cve_id} 버전 범위 불일치 — 제외 ({version})")
            continue

        results.append({
            "id":             cve_id,
            "severity":       severity.upper(),
            "score":          score,
            "description":    desc[:200] if desc else "",
            "url":            f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "configurations": configurations,
        })

    return results


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
            evidence=f"{path} HTTP 403 반환 — 파일이 존재하나 접근 차단됨",
        )]

    # [High-1] 3xx 리다이렉트: 따라가서 최종 응답 분석
    if resp.status_code in (301, 302, 303, 307, 308):
        followed = _get(url, follow=True)
        if followed is None or followed.status_code != 200:
            return []
        if _is_login_page(followed.text):
            print(f"[MISCONFIG] WARNING {category} (302→login): {url}")
            return [misconfig_finding(
                type=MISCONFIG_WARNING,
                category=category,
                url=url,
                status=resp.status_code,
                confidence=LOW,
                evidence=f"{path} 로그인 페이지로 리다이렉트 — 인증 뒤에 파일이 존재할 수 있음",
            )]
        found, evidence = _match_keywords(followed.text, rule_key)
        if found:
            print(f"[MISCONFIG] CONFIRMED {category} (via redirect): {url}")
            return [misconfig_finding(
                type=MISCONFIG_CONFIRMED,
                category=category,
                url=url,
                status=resp.status_code,
                confidence=HIGH,
                evidence=evidence,
            )]
        return []

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

    # [High-2] 200이지만 키워드 없음 — 로그인 페이지면 오탐이므로 제외
    if _is_login_page(resp.text):
        return []

    body_stripped = resp.text.strip()
    if len(body_stripped) > _MIN_BODY_LEN:
        print(f"[MISCONFIG] WARNING {category} (200, no keyword match): {url}")
        return [misconfig_finding(
            type=MISCONFIG_WARNING,
            category=category,
            url=url,
            status=resp.status_code,
            confidence=LOW,
            evidence=f"{path} HTTP 200 반환 ({len(body_stripped)} bytes) — 수동 확인 권장",
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
    is_https = base_url.startswith("https://")

    resp = _head(home_url)
    if resp is None:
        resp = _get(home_url)
    if resp is None:
        return findings

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    # 1. 보안 헤더 누락 — 헤더별 가중치 적용
    for header_name, category, ftype, confidence in _SECURITY_HEADERS:
        # HSTS는 HTTPS 사이트에만 의미 있음
        if header_name == "Strict-Transport-Security" and not is_https:
            continue
        if header_name.lower() not in headers_lower:
            print(f"[MISCONFIG] {ftype} missing_header ({confidence}): {header_name}")
            findings.append(misconfig_finding(
                type=ftype,
                category="missing_security_header",
                url=home_url,
                status=resp.status_code,
                confidence=confidence,
                evidence=f"보안 헤더 누락: {header_name}",
                extra={"header": header_name, "category": category},
            ))

    # 2. 버전 헤더 탐지 + NVD CVE 조회
    api_key = os.environ.get("NVD_API_KEY")
    queried = 0
    for header_name in _VERSION_HEADERS:
        value = headers_lower.get(header_name.lower())
        if not value:
            continue

        parsed = _parse_product_version(value)

        if parsed:
            vendor, product, version = parsed
            if queried > 0 and not api_key:
                time.sleep(_NVD_RATE_LIMIT_DELAY)
            print(f"[MISCONFIG] NVD 조회: {header_name}: {value} → cpe:2.3:a:{vendor}:{product}:{version}:*")
            cves = _query_nvd_cves(vendor, product, version)
            queried += 1

            if cves:
                top      = max(cves, key=lambda c: c.get("score") or 0)
                top_sev  = top.get("severity", "UNKNOWN")
                ftype    = MISCONFIG_CONFIRMED if top_sev in ("CRITICAL", "HIGH") else MISCONFIG_WARNING
                conf     = HIGH if top_sev in ("CRITICAL", "HIGH") else MEDIUM
                cve_ids  = ", ".join(c["id"] for c in cves[:3])
                evidence = (
                    f"버전 정보 노출: {header_name}: {value} "
                    f"→ CVE {len(cves)}건 "
                    f"(주요: {top['id']} {top_sev} 점수={top.get('score')})"
                )
                print(f"[MISCONFIG] {ftype} version+CVE: {header_name}: {value} → {cve_ids}")
                cve_links = [
                    {"id": c["id"], "score": c.get("score"), "severity": c.get("severity"), "url": c.get("url", "")}
                    for c in cves[:5]
                ]
                findings.append(misconfig_finding(
                    type=ftype,
                    category="version_disclosure",
                    url=home_url,
                    status=resp.status_code,
                    confidence=conf,
                    evidence=evidence,
                    extra={"header": header_name, "value": value, "cves": cves, "cve_links": cve_links},
                ))
            else:
                print(f"[MISCONFIG] WARNING version_disclosure (CVE 없음): {header_name}: {value}")
                findings.append(misconfig_finding(
                    type=MISCONFIG_WARNING,
                    category="version_disclosure",
                    url=home_url,
                    status=resp.status_code,
                    confidence=LOW,
                    evidence=f"버전 정보 노출: {header_name}: {value} (관련 CVE 없음)",
                    extra={"header": header_name, "value": value, "cves": []},
                ))
        else:
            # 알 수 없는 제품 — 버전 노출만 기록
            print(f"[MISCONFIG] WARNING version_disclosure: {header_name}: {value}")
            findings.append(misconfig_finding(
                type=MISCONFIG_WARNING,
                category="version_disclosure",
                url=home_url,
                status=resp.status_code,
                confidence=MEDIUM,
                evidence=f"헤더를 통한 버전 정보 노출: {header_name}: {value}",
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
            evidence=f"응답에 에러 메시지 노출: {m.group(0)[:100]}",
        ))

    return findings


def _check_cookies(base_url: str) -> list[dict]:
    findings = []
    home_url = base_url + "/"
    resp = _get(home_url)
    if resp is None:
        return findings
    try:
        raw_cookies = resp.raw.headers.getlist("set-cookie")
    except AttributeError:
        raw_cookies = [v for k, v in resp.raw.headers.items() if k.lower() == "set-cookie"]
    for raw in raw_cookies:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=")[0].strip() if parts else "unknown"
        attrs_lower = {p.lower() for p in parts[1:]}
        issues = []
        if "secure" not in attrs_lower:
            issues.append("Secure 플래그 누락")
        if "httponly" not in attrs_lower:
            issues.append("HttpOnly 플래그 누락")
        if not any(a.startswith("samesite") for a in attrs_lower):
            issues.append("SameSite 속성 누락")
        if issues:
            confidence = HIGH if len(issues) >= 2 else MEDIUM
            print(f"[MISCONFIG] WARNING insecure_cookie: {name} → {', '.join(issues)}")
            findings.append(misconfig_finding(
                type=MISCONFIG_WARNING,
                category="insecure_cookie",
                url=home_url,
                status=resp.status_code,
                confidence=confidence,
                evidence=f"쿠키 '{name}' 보안 속성 문제: {', '.join(issues)}",
                extra={"cookie_name": name, "issues": issues},
            ))
    return findings


def _check_cors(base_url: str) -> list[dict]:
    findings = []
    home_url = base_url + "/"
    headers = {**_REQUEST_HEADERS, "Origin": "https://evil.example.com"}
    try:
        resp = requests.get(home_url, headers=headers, timeout=10, allow_redirects=False)
    except requests.exceptions.RequestException:
        return findings
    acao = resp.headers.get("Access-Control-Allow-Origin", "")
    acac = resp.headers.get("Access-Control-Allow-Credentials", "").lower()
    if acao == "*":
        print(f"[MISCONFIG] WARNING cors_wildcard: Access-Control-Allow-Origin: *")
        findings.append(misconfig_finding(
            type=MISCONFIG_WARNING,
            category="cors_wildcard",
            url=home_url,
            status=resp.status_code,
            confidence=MEDIUM,
            evidence="Access-Control-Allow-Origin: * — 모든 출처 허용 (CORS 설정 취약)",
            extra={"header": "Access-Control-Allow-Origin", "value": acao},
        ))
    elif acao and "evil.example.com" in acao and acac == "true":
        print(f"[MISCONFIG] CONFIRMED cors_origin_reflection: {acao} + credentials")
        findings.append(misconfig_finding(
            type=MISCONFIG_CONFIRMED,
            category="cors_origin_reflection",
            url=home_url,
            status=resp.status_code,
            confidence=HIGH,
            evidence=f"CORS 임의 출처 반사 + 자격증명 허용: {acao} + Access-Control-Allow-Credentials: true",
            extra={"acao": acao, "acac": acac},
        ))
    return findings


_ADMIN_PATHS: list[tuple[str, str]] = [
    ("/admin",          "admin_panel"),
    ("/admin/",         "admin_panel"),
    ("/administrator/", "admin_panel"),
    ("/admin.php",      "admin_panel"),
    ("/phpmyadmin/",    "phpmyadmin"),
    ("/phpmyadmin",     "phpmyadmin"),
    ("/wp-admin/",      "wordpress_admin"),
    ("/wp-login.php",   "wordpress_admin"),
    ("/manager/html",   "tomcat_manager"),
    ("/console",        "admin_console"),
    ("/dashboard",      "admin_dashboard"),
]


def _check_admin_pages(base_url: str) -> list[dict]:
    findings = []
    for path, category in _ADMIN_PATHS:
        url = base_url + path
        resp = _get(url)
        if resp is None:
            continue
        if resp.status_code == 200:
            print(f"[MISCONFIG] WARNING admin_page_exposed (200): {url}")
            findings.append(misconfig_finding(
                type=MISCONFIG_WARNING,
                category="admin_page_exposed",
                url=url,
                status=200,
                confidence=MEDIUM,
                evidence=f"관리자 페이지 접근 가능: {path}",
                extra={"path": path, "admin_type": category},
            ))
        elif resp.status_code == 403:
            print(f"[MISCONFIG] WARNING admin_page_exists (403): {url}")
            findings.append(misconfig_finding(
                type=MISCONFIG_WARNING,
                category="admin_page_exists",
                url=url,
                status=403,
                confidence=LOW,
                evidence=f"관리자 페이지 존재 (403 접근 차단): {path}",
                extra={"path": path, "admin_type": category},
            ))
    return findings


_ROBOTS_SENSITIVE_KEYWORDS = [
    "admin", "backup", "config", "private", "secret",
    "database", "db", "sql", "upload", "internal", "log",
]


def _check_robots_txt(base_url: str) -> list[dict]:
    findings = []
    url = base_url + "/robots.txt"
    resp = _get(url)
    if resp is None or resp.status_code != 200:
        return findings
    disallow_paths = []
    for line in resp.text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                disallow_paths.append(path)
    sensitive = [p for p in disallow_paths if any(kw in p.lower() for kw in _ROBOTS_SENSITIVE_KEYWORDS)]
    if sensitive:
        print(f"[MISCONFIG] WARNING robots_txt: {len(sensitive)}개 민감 경로 노출")
        findings.append(misconfig_finding(
            type=MISCONFIG_WARNING,
            category="robots_txt_sensitive_paths",
            url=url,
            status=200,
            confidence=LOW,
            evidence=f"robots.txt에 민감 경로 {len(sensitive)}개 노출: {', '.join(sensitive[:5])}",
            extra={"sensitive_paths": sensitive},
        ))
    return findings


# ── 메인 체크 함수 ────────────────────────────────────────────

def check(base_url: str, progress_callback=None) -> list[dict]:
    base_url = normalize_base_url(base_url)
    findings: list[dict] = []

    total = len(_SENSITIVE_FILES) + len(_DIRECTORY_PATHS) + 6
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

    print("[MISCONFIG] checking 쿠키 보안 속성...")
    findings.extend(_check_cookies(base_url))
    _tick()

    print("[MISCONFIG] checking CORS 설정...")
    findings.extend(_check_cors(base_url))
    _tick()

    print(f"[MISCONFIG] checking 관리자 페이지... ({len(_ADMIN_PATHS)}개)")
    findings.extend(_check_admin_pages(base_url))
    _tick()

    print("[MISCONFIG] checking robots.txt...")
    findings.extend(_check_robots_txt(base_url))
    _tick()

    return findings


# ── run: 외부 진입점 ──────────────────────────────────────────

def run(
    base_url: str,
    output_file: str = "results/findings.json",
    progress_callback=None,
    append: bool = True,
) -> list[dict]:

    print(f"[MISCONFIG] start → {base_url}")
    findings = check(base_url, progress_callback=progress_callback)

    confirmed = sum(1 for f in findings if f.get("type") == MISCONFIG_CONFIRMED)
    warnings  = sum(1 for f in findings if f.get("type") == MISCONFIG_WARNING)
    print(f"[MISCONFIG] done: confirmed={confirmed}, warning={warnings}, total={len(findings)}")

    if append:
        append_findings(findings, output_file)
    else:
        save_json(output_file, findings)

    return findings


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8081"
    result = run(target, output_file="results/misconfig_findings.json", append=False)
    print(f"\n총 {len(result)}개 발견")
    for f in result:
        print(f"  [{f['type']:22s}] [{f['confidence']:6s}] {f['category']:25s} {f['url']}")
        print(f"    → {f['evidence']}")
