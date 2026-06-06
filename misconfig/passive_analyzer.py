"""
misconfig/passive_analyzer.py — mitmproxy 애드온

크롤링 중 모든 HTTP 응답이 지나갈 때 자동으로 패시브 분석 실행.
보안 헤더, 쿠키, CORS, 에러/버전 노출 탐지.
"""
from __future__ import annotations

import re
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mitmproxy import http
from findings import misconfig_finding, MISCONFIG_CONFIRMED, MISCONFIG_WARNING, HIGH, MEDIUM, LOW

_SECURITY_HEADERS = [
    ("Content-Security-Policy",   "csp",                    MISCONFIG_CONFIRMED, HIGH),
    ("Strict-Transport-Security", "hsts",                    MISCONFIG_CONFIRMED, HIGH),
    ("X-Frame-Options",           "clickjacking_protection", MISCONFIG_WARNING,   MEDIUM),
    ("X-Content-Type-Options",    "mime_sniffing_protection", MISCONFIG_WARNING,  MEDIUM),
    ("Referrer-Policy",           "referrer_policy",          MISCONFIG_WARNING,  LOW),
    ("X-XSS-Protection",          "xss_header",               MISCONFIG_WARNING,  LOW),
]

_VERSION_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]

_ERROR_PATTERN = re.compile(
    r"(PHP (Warning|Fatal|Notice|Parse)|SQL syntax|mysql_fetch|"
    r"ORA-\d{5}|Microsoft OLE DB|ODBC.*error|Warning:.*on line \d+|"
    r"Stack trace:|Traceback \(most recent call last\))",
    re.IGNORECASE,
)


class PassiveAnalyzer:
    """mitmproxy 애드온 — response() 메서드가 응답마다 자동 호출됨"""

    def __init__(self, findings_list: list, target_host: str = ""):
        self.findings = findings_list
        self.target_host = target_host          # 이 호스트 응답만 분석
        self._seen_hosts: set[str] = set()      # 보안 헤더는 호스트당 1번
        self._seen_versions: set[str] = set()   # 버전 헤더는 값당 1번
        self._seen_cookies: set[str] = set()    # 쿠키는 (이름+이슈) 조합당 1번
        self._seen_cors: set[str] = set()       # CORS는 호스트당 1번
        self._seen_errors: set[str] = set()     # 에러 패턴은 패턴당 1번

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None:
            return

        host = flow.request.host
        # 타깃 호스트 응답만 분석 — 외부 사이트 제외
        if self.target_host and host != self.target_host:
            return

        url    = flow.request.pretty_url
        status = flow.response.status_code
        headers_lower = {k.lower(): v for k, v in flow.response.headers.items()}

        # 보안 헤더 누락 — 호스트당 1번만
        if host not in self._seen_hosts:
            self._seen_hosts.add(host)
            self._check_security_headers(url, headers_lower, status)

        # 쿠키 속성 — Set-Cookie 있을 때마다
        for raw in flow.response.headers.get_all("set-cookie"):
            self._check_cookie(url, raw, status)

        # CORS
        self._check_cors(url, headers_lower, status)

        # 에러/버전 노출 — HTML 응답만
        content_type = headers_lower.get("content-type", "")
        if "html" in content_type or "text/plain" in content_type:
            try:
                body = flow.response.get_text(strict=False)
                self._check_error(url, body, status)
            except Exception:
                pass

        # 버전 헤더 — 새 값 발견 시만
        self._check_version_headers(url, headers_lower, status)

    # ── 개별 분석 함수 ────────────────────────────────────────────

    def _check_security_headers(self, url: str, headers_lower: dict, status: int) -> None:
        is_https = url.startswith("https://")
        for header_name, category, ftype, confidence in _SECURITY_HEADERS:
            if header_name == "Strict-Transport-Security" and not is_https:
                continue
            if header_name.lower() not in headers_lower:
                self.findings.append(misconfig_finding(
                    type=ftype,
                    category="missing_security_header",
                    url=url,
                    status=status,
                    confidence=confidence,
                    evidence=f"보안 헤더 누락: {header_name}",
                    extra={"header": header_name, "category": category},
                ))

    def _check_cookie(self, url: str, raw: str, status: int) -> None:
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
        if not issues:
            return
        # 같은 쿠키+이슈 조합은 1번만 리포트
        dedup_key = f"{name}|{'|'.join(sorted(issues))}"
        if dedup_key in self._seen_cookies:
            return
        self._seen_cookies.add(dedup_key)
        confidence = HIGH if len(issues) >= 2 else MEDIUM
        self.findings.append(misconfig_finding(
            type=MISCONFIG_WARNING,
            category="insecure_cookie",
            url=url,
            status=status,
            confidence=confidence,
            evidence=f"쿠키 '{name}' 보안 속성 문제: {', '.join(issues)}",
            extra={"cookie_name": name, "issues": issues},
        ))

    def _check_cors(self, url: str, headers_lower: dict, status: int) -> None:
        from urllib.parse import urlparse
        host = urlparse(url).netloc
        if host in self._seen_cors:
            return
        acao = headers_lower.get("access-control-allow-origin", "")
        acac = headers_lower.get("access-control-allow-credentials", "").lower()
        if acao == "*":
            self._seen_cors.add(host)
            self.findings.append(misconfig_finding(
                type=MISCONFIG_WARNING,
                category="cors_wildcard",
                url=url,
                status=status,
                confidence=MEDIUM,
                evidence="Access-Control-Allow-Origin: * — 모든 출처 허용 (CORS 설정 취약)",
                extra={"header": "Access-Control-Allow-Origin", "value": acao},
            ))
        elif acao and acac == "true":
            self._seen_cors.add(host)
            self.findings.append(misconfig_finding(
                type=MISCONFIG_CONFIRMED,
                category="cors_origin_reflection",
                url=url,
                status=status,
                confidence=HIGH,
                evidence=f"CORS 임의 출처 반사 + 자격증명 허용: {acao}",
                extra={"acao": acao, "acac": acac},
            ))

    def _check_error(self, url: str, body: str, status: int) -> None:
        m = _ERROR_PATTERN.search(body)
        if not m:
            return
        dedup_key = m.group(0)[:60]
        if dedup_key in self._seen_errors:
            return
        self._seen_errors.add(dedup_key)
        self.findings.append(misconfig_finding(
            type=MISCONFIG_CONFIRMED,
            category="error_disclosure",
            url=url,
            status=status,
            confidence=HIGH,
            evidence=f"응답에 에러 메시지 노출: {m.group(0)[:100]}",
        ))

    def _check_version_headers(self, url: str, headers_lower: dict, status: int) -> None:
        for header_name in _VERSION_HEADERS:
            value = headers_lower.get(header_name.lower())
            if not value:
                continue
            key = f"{header_name}:{value}"
            if key in self._seen_versions:
                continue
            self._seen_versions.add(key)
            self.findings.append(misconfig_finding(
                type=MISCONFIG_WARNING,
                category="version_disclosure",
                url=url,
                status=status,
                confidence=MEDIUM,
                evidence=f"버전 정보 노출: {header_name}: {value}",
                extra={"header": header_name, "value": value},
            ))
