"""
misconfig/proxy_runner.py — mitmproxy 생명주기 관리

크롤링 시작 전 프록시를 띄우고, 크롤링 끝나면 종료.
수집된 패시브 findings 반환.
"""
from __future__ import annotations

import asyncio
import logging
import threading

from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from .passive_analyzer import PassiveAnalyzer

_DEFAULT_PORT = 8899

# mitmproxy 관련 로거를 CRITICAL로 — 일반 로그 출력 차단
for _logger_name in ("mitmproxy", "mitmproxy.proxy", "mitmproxy.flow",
                     "asyncio", "wsproto", "h2"):
    logging.getLogger(_logger_name).setLevel(logging.CRITICAL)


class ProxyRunner:
    def __init__(self, port: int = _DEFAULT_PORT, target_url: str = ""):
        self.port        = port
        self.target_url  = target_url
        self.findings: list[dict] = []
        self._master: DumpMaster | None = None
        self._thread: threading.Thread | None = None
        self._loop:   asyncio.AbstractEventLoop | None = None
        self._ready   = threading.Event()
        self._error:  Exception | None = None

    # ── 시작 ──────────────────────────────────────────────────────

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="mitmproxy")
        self._thread.start()
        if not self._ready.wait(timeout=8):
            raise RuntimeError("[PROXY] 프록시 시작 실패 (timeout)")
        if self._error:
            raise self._error
        print(f"[PROXY] 프록시 준비 완료: 127.0.0.1:{self.port}")

    def _run_loop(self) -> None:
        self._loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self._loop)
        try:
            self._loop.run_until_complete(self._run_proxy())
        except Exception as e:
            self._error = e
            self._ready.set()

    async def _run_proxy(self) -> None:
        from urllib.parse import urlparse
        target_host = urlparse(self.target_url).hostname or ""
        opts = options.Options(
            listen_host="127.0.0.1",
            listen_port=self.port,
            ssl_insecure=True,
        )
        self._master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        self._master.addons.add(PassiveAnalyzer(self.findings, target_host=target_host))
        self._ready.set()
        await self._master.run()

    # ── 종료 ──────────────────────────────────────────────────────

    def stop(self) -> None:
        if self._master:
            self._master.shutdown()
        if self._thread:
            self._thread.join(timeout=5)
        print(f"[PROXY] 종료. 패시브 findings: {len(self.findings)}개")

    # ── 컨텍스트 매니저 ───────────────────────────────────────────

    def __enter__(self) -> "ProxyRunner":
        self.start()
        return self

    def __exit__(self, *_) -> None:
        self.stop()

    # ── 프록시 설정 (크롤러 세션에 주입용) ──────────────────────

    @property
    def proxies(self) -> dict[str, str]:
        addr = f"http://127.0.0.1:{self.port}"
        return {"http": addr, "https": addr}
