"""代理感知HTTP客户端"""

from __future__ import annotations

import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)


class HttpClient:
    """封装httpx，支持SOCKS5/HTTP代理和统一超时"""

    def __init__(self, proxy: str = "", timeout: float = 15) -> None:
        transport = httpx.AsyncHTTPTransport(proxy=proxy) if proxy else None
        self._client = httpx.AsyncClient(
            transport=transport,
            timeout=httpx.Timeout(timeout),
            follow_redirects=True,
            max_redirects=10,
            verify=False,
            limits=httpx.Limits(max_connections=20, max_keepalive_connections=10),
        )

    async def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, Any] | None = None,
        json: dict[str, Any] | None = None,
        data: Any = None,
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> httpx.Response:
        logger.debug("%s %s", method, url)
        return await self._client.request(
            method, url, params=params, json=json, data=data,
            headers=headers, cookies=cookies,
        )

    async def close(self) -> None:
        await self._client.aclose()
