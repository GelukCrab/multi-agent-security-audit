"""HTTP交互工具"""

from __future__ import annotations

import time
import logging
from src.utils.http_client import HttpClient

logger = logging.getLogger(__name__)

RESPONSE_TRUNCATE = 3000


def create_http_tools(client: HttpClient) -> dict:
    """创建HTTP工具集，返回{name: handler}"""

    async def http_request(
        method: str, url: str,
        params: dict | None = None,
        headers: dict | None = None,
        body: str | None = None,
        content_type: str | None = None,
    ) -> dict:
        """发送HTTP请求"""
        req_headers = dict(headers or {})
        if content_type:
            req_headers["Content-Type"] = content_type

        json_data = None
        data = None
        if body and content_type and "json" in content_type:
            import json
            try:
                json_data = json.loads(body)
            except Exception:
                data = {"raw": body}
        elif body:
            data = {"raw": body}

        start = time.time()
        try:
            resp = await client.request(
                method, url, params=params,
                headers=req_headers if req_headers else None,
                json=json_data, data=data,
            )
            elapsed = time.time() - start
            body_text = resp.text[:RESPONSE_TRUNCATE]
            return {
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": body_text,
                "elapsed_seconds": round(elapsed, 2),
                "body_length": len(resp.text),
            }
        except Exception as e:
            return {"error": str(e)}

    async def fetch_page(url: str) -> dict:
        """获取页面HTML内容"""
        try:
            resp = await client.request("GET", url)
            html = resp.text[:5000]
            title = ""
            import re
            m = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
            if m:
                title = m.group(1).strip()
            return {
                "status_code": resp.status_code,
                "html": html,
                "title": title,
                "content_length": len(resp.text),
            }
        except Exception as e:
            return {"error": str(e)}

    return {
        "http_request": http_request,
        "fetch_page": fetch_page,
    }
