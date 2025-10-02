from __future__ import annotations

import asyncio
from typing import Any

from aiohttp import ClientSession, ClientTimeout


class HttpClientManager:
    __slots__ = ("_timeout", "_session", "_lock")

    def __init__(self, total_timeout: float = 15.0) -> None:
        self._timeout = ClientTimeout(total=total_timeout)
        self._session: ClientSession | None = None
        self._lock = asyncio.Lock()

    async def startup(self) -> None:
        async with self._lock:
            if self._session is None or self._session.closed:
                self._session = ClientSession(timeout=self._timeout)

    async def shutdown(self) -> None:
        async with self._lock:
            if self._session and not self._session.closed:
                await self._session.close()
            self._session = None

    @property
    def session(self) -> ClientSession:
        if self._session is None or self._session.closed:
            raise RuntimeError("HTTP client session is not started")
        return self._session

    async def request(self, method: str, url: str, **kwargs: Any):
        await self.startup()
        return await self.session.request(method, url, **kwargs)

