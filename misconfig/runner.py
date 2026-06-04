"""
misconfig/runner.py — misconfig 진단 오케스트레이터

bac/runner.py와 대칭 구조.
  입력: target URL
  처리: ssl_checker(SSL/TLS) + checker(파일/헤더/에러/쿠키/CORS/관리자/robots)
  출력: misconfig finding 리스트

tasks.py _task_misconfig 와 _task_all 내 병렬 스레드 모두 이 함수를 호출한다.
"""
from __future__ import annotations

from .checker import check as checker_check
from .ssl_checker import check_ssl


def build_misconfig_results(
    base_url: str,
    progress_callback=None,
) -> list[dict]:
    """
    전체 misconfig 진단 실행.
    bac/runner.py build_bac_results와 대칭.

    반환: misconfig finding 리스트
    """
    base_url = base_url.rstrip("/")
    findings: list[dict] = []

    # 1. SSL/TLS 체크
    print(f"[MISCONFIG] SSL/TLS 체크 시작: {base_url}")
    ssl_findings = check_ssl(base_url)
    findings.extend(ssl_findings)
    print(f"[MISCONFIG] SSL/TLS 완료: {len(ssl_findings)}개")

    # 2. 파일/헤더/에러/쿠키/CORS/관리자페이지/robots 체크
    checker_findings = checker_check(base_url, progress_callback=progress_callback)
    findings.extend(checker_findings)

    confirmed = sum(1 for f in findings if f.get("type") == "MISCONFIG_CONFIRMED")
    warnings  = sum(1 for f in findings if f.get("type") == "MISCONFIG_WARNING")
    print(f"[MISCONFIG] runner 완료: confirmed={confirmed}, warning={warnings}, total={len(findings)}")

    return findings
