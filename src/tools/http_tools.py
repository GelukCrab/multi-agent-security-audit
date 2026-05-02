"""HTTP交互工具"""

from __future__ import annotations

import re
import time
import logging
from urllib.parse import unquote
from src.utils.http_client import HttpClient

logger = logging.getLogger(__name__)

RESPONSE_TRUNCATE = 5000

# httpx不支持URL中的非打印ASCII字符，保留这些的编码形式
_UNSAFE_PERCENT = re.compile(r'%(?:0[0-9a-fA-F]|1[0-9a-fA-F]|7[fF])', re.IGNORECASE)


def _safe_unquote_url(url: str) -> str:
    """选择性URL解码：解码安全字符，保留非打印字符的%编码"""
    # 先把不安全的%编码临时替换
    placeholders = {}
    counter = [0]

    def _replace(m):
        key = f"__PH{counter[0]}__"
        placeholders[key] = m.group(0)
        counter[0] += 1
        return key

    safe_url = _UNSAFE_PERCENT.sub(_replace, url)
    # 解码安全字符
    safe_url = unquote(safe_url)
    # 还原不安全的编码
    for key, val in placeholders.items():
        safe_url = safe_url.replace(key, val)
    return safe_url


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
        # 模型可能输出已编码的URL，选择性解码防止双重编码
        # 但保留非打印字符的编码形式（%0a %09 %0b %0c %0d等），httpx不支持这些
        if "%" in url:
            url = _safe_unquote_url(url)
            logger.debug("URL处理后: %s", url[:200])

        req_headers = dict(headers or {})
        if content_type:
            req_headers["Content-Type"] = content_type

        json_data = None
        data = None
        if body:
            # body也可能被编码
            if "%" in body:
                body = _safe_unquote_url(body)
                logger.debug("Body解码后: %s", body[:200])
            if content_type and "json" in content_type:
                import json
                try:
                    json_data = json.loads(body)
                except json.JSONDecodeError:
                    data = body
            else:
                data = body

        # 过滤空params — 空dict会导致httpx覆盖URL中的query string
        if not params:
            params = None

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
                "truncated": len(resp.text) > RESPONSE_TRUNCATE,
            }
        except Exception as e:
            logger.error("HTTP请求失败 %s %s: %s", method, url, e)
            return {"error": f"{type(e).__name__}: {e}"}

    async def fetch_page(url: str) -> dict:
        """获取页面HTML内容"""
        try:
            resp = await client.request("GET", url)
            html = resp.text[:RESPONSE_TRUNCATE]
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
            logger.error("fetch_page失败 %s: %s", url, e)
            return {"error": f"{type(e).__name__}: {e}"}

    return {
        "http_request": http_request,
        "fetch_page": fetch_page,
    }
