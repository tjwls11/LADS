"""
misconfig/ssl_checker.py — SSL/TLS 보안 체크

체크 항목:
  - HTTPS 미사용 (HTTP only)
  - SSL 인증서 만료 / 만료 임박 (30일)
  - 취약한 TLS 버전 사용 (TLS 1.0 / 1.1)
  - 인증서 검증 실패 (자체 서명, 호스트명 불일치 등)
"""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

from findings import misconfig_finding, MISCONFIG_CONFIRMED, MISCONFIG_WARNING, HIGH, MEDIUM, LOW

_WEAK_PROTOCOLS = {"TLSv1", "TLSv1.1", "SSLv2", "SSLv3"}


def check_ssl(base_url: str) -> list[dict]:
    findings: list[dict] = []
    parsed = urlparse(base_url.rstrip("/"))

    # ── 1. HTTPS 미사용 ──────────────────────────────────────────
    if parsed.scheme == "http":
        print("[SSL] CONFIRMED no_https: site uses HTTP only")
        findings.append(misconfig_finding(
            type=MISCONFIG_CONFIRMED,
            category="no_https",
            url=base_url,
            status=0,
            confidence=HIGH,
            evidence="HTTPS 미사용 — 데이터가 평문으로 전송됨",
        ))
        return findings  # HTTPS 아니면 이후 체크 불가

    hostname = parsed.hostname
    port = parsed.port or 443

    # ── 2. 인증서 검증 실패 탐지 ────────────────────────────────
    ctx_strict = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with ctx_strict.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

                # TLS 버전 체크
                if protocol in _WEAK_PROTOCOLS:
                    print(f"[SSL] CONFIRMED weak_tls_version: {protocol}")
                    findings.append(misconfig_finding(
                        type=MISCONFIG_CONFIRMED,
                        category="weak_tls_version",
                        url=base_url,
                        status=0,
                        confidence=HIGH,
                        evidence=f"취약한 TLS 버전 사용: {protocol} (TLS 1.2 이상 권장)",
                    ))
                else:
                    print(f"[SSL] OK protocol: {protocol}")

                # 인증서 만료 체크
                not_after = cert.get("notAfter")
                if not_after:
                    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
                    now = datetime.now(tz=timezone.utc)
                    days_left = (expiry - now).days
                    if days_left < 0:
                        print(f"[SSL] CONFIRMED expired_certificate: {abs(days_left)}일 초과")
                        findings.append(misconfig_finding(
                            type=MISCONFIG_CONFIRMED,
                            category="expired_certificate",
                            url=base_url,
                            status=0,
                            confidence=HIGH,
                            evidence=f"SSL 인증서 만료됨 ({abs(days_left)}일 초과, 만료일: {not_after})",
                        ))
                    elif days_left < 30:
                        print(f"[SSL] WARNING expiring_certificate: {days_left}일 남음")
                        findings.append(misconfig_finding(
                            type=MISCONFIG_WARNING,
                            category="expiring_certificate",
                            url=base_url,
                            status=0,
                            confidence=MEDIUM,
                            evidence=f"SSL 인증서 만료 임박 ({days_left}일 남음, 만료일: {not_after})",
                        ))
                    else:
                        print(f"[SSL] OK certificate: {days_left}일 남음")

    except ssl.SSLCertVerificationError as e:
        print(f"[SSL] CONFIRMED invalid_certificate: {e.reason}")
        findings.append(misconfig_finding(
            type=MISCONFIG_CONFIRMED,
            category="invalid_certificate",
            url=base_url,
            status=0,
            confidence=HIGH,
            evidence=f"SSL 인증서 검증 실패: {e.reason}",
        ))
    except ssl.SSLError as e:
        print(f"[SSL] WARNING ssl_error: {e}")
        findings.append(misconfig_finding(
            type=MISCONFIG_WARNING,
            category="ssl_error",
            url=base_url,
            status=0,
            confidence=MEDIUM,
            evidence=f"SSL 핸드셰이크 오류: {e}",
        ))
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        print(f"[SSL] 연결 실패 (무시): {e}")

    return findings
