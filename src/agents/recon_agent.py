"""侦察Agent — 攻击面枚举"""

from __future__ import annotations

import re
import json
import logging
from urllib.parse import urljoin, urlparse

from src.core import (
    Endpoint, Parameter, HttpMethod, Priority, AgentMessage,
)
from src.core.message_bus import MessageBus
from src.utils.http_client import HttpClient
from src.utils.fingerprint import identify_framework, COMMON_LEAK_PATHS

logger = logging.getLogger(__name__)

JS_API_PATTERN = re.compile(
    r"""(?:["'`])((?:/api/|/v[0-9]+/)[a-zA-Z0-9_/\-{}]+)(?:["'`])""", re.IGNORECASE
)
JS_GENERIC_PATH_PATTERN = re.compile(
    r"""(?:["'`])(/[a-zA-Z][a-zA-Z0-9_/\-{}]*?)(?:["'`])"""
)
SWAGGER_PATHS = [
    "/swagger-ui.html", "/swagger-ui/", "/swagger-ui/index.html",
    "/v2/api-docs", "/v3/api-docs", "/api-docs",
    "/apispec_1.json", "/apispec.json", "/spec.json",
]
MAX_JS_SIZE = 500_000


class ReconAgent:
    """攻击面枚举Agent：爬取JS、解析API文档、探测泄露路径"""

    def __init__(
        self, base_url: str, client: HttpClient, bus: MessageBus,
        js_crawl_depth: int = 3, parse_swagger: bool = True,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.client = client
        self.bus = bus
        self.js_crawl_depth = js_crawl_depth
        self.parse_swagger = parse_swagger
        self._endpoints: dict[str, Endpoint] = {}
        self._js_urls: set[str] = set()

    async def run(self) -> list[Endpoint]:
        """执行完整侦察流程"""
        logger.info("===== 侦察Agent启动 =====")
        logger.info("目标: %s", self.base_url)

        frameworks = await identify_framework(self.client._client, self.base_url)
        logger.info("框架指纹: %s", frameworks)

        await self._crawl_homepage()
        await self._extract_js_apis()

        if self.parse_swagger:
            await self._parse_swagger_docs()

        await self._probe_leak_paths()
        self._assign_priorities()

        endpoints = list(self._endpoints.values())
        logger.info("枚举完成，共发现 %d 个端点", len(endpoints))

        await self.bus.publish(AgentMessage(
            sender="recon", receiver="analyzer",
            msg_type="endpoints", payload=endpoints,
        ))
        return endpoints

    async def _crawl_homepage(self) -> None:
        """爬取首页，提取JS文件链接和内联API路径"""
        try:
            resp = await self.client.request("GET", self.base_url)
            js_links = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', resp.text)
            for link in js_links:
                full_url = urljoin(self.base_url, link)
                self._js_urls.add(full_url)

            for match in JS_API_PATTERN.finditer(resp.text):
                self._add_endpoint(match.group(1), HttpMethod.GET)

            logger.info("首页发现 %d 个JS文件, %d 个内联API", len(js_links), len(self._endpoints))
        except Exception as e:
            logger.warning("首页爬取失败: %s", e)

    async def _extract_js_apis(self) -> None:
        """从JS文件中提取API路径"""
        for js_url in list(self._js_urls):
            try:
                resp = await self.client.request("GET", js_url)
                if len(resp.text) > MAX_JS_SIZE:
                    logger.debug("跳过大JS文件: %s (%d bytes)", js_url, len(resp.text))
                    continue
                for match in JS_API_PATTERN.finditer(resp.text):
                    path = match.group(1)
                    method = HttpMethod.POST if "create" in path or "add" in path or "login" in path else HttpMethod.GET
                    self._add_endpoint(path, method)
                for match in JS_GENERIC_PATH_PATTERN.finditer(resp.text):
                    path = match.group(1)
                    if len(path) > 4 and not path.endswith((".js", ".css", ".png", ".jpg", ".svg", ".ico", ".woff")):
                        self._add_endpoint(path, HttpMethod.GET)
            except Exception:
                continue
        logger.info("JS分析后端点总数: %d", len(self._endpoints))

    async def _parse_swagger_docs(self) -> None:
        """尝试解析Swagger/OpenAPI文档"""
        for swagger_path in SWAGGER_PATHS:
            url = f"{self.base_url}{swagger_path}"
            try:
                resp = await self.client.request("GET", url)
                if resp.status_code != 200:
                    continue
                data = resp.json()
                paths = data.get("paths", {})
                for path, methods in paths.items():
                    for method_str, detail in methods.items():
                        if method_str.upper() not in HttpMethod.__members__:
                            continue
                        method = HttpMethod(method_str.upper())
                        params = []
                        for p in detail.get("parameters", []):
                            params.append(Parameter(
                                name=p.get("name", ""),
                                location=p.get("in", "query"),
                                param_type=p.get("type", "string"),
                                required=p.get("required", False),
                            ))
                        ep = self._add_endpoint(path, method)
                        ep.parameters = params
                        ep.description = detail.get("summary", "")
                logger.info("Swagger解析成功: %s, 新增路径 %d", swagger_path, len(paths))
                return
            except Exception:
                continue

    async def _probe_leak_paths(self) -> None:
        """探测常见泄露路径"""
        for leak_path in COMMON_LEAK_PATHS:
            url = f"{self.base_url}{leak_path}"
            try:
                resp = await self.client.request("GET", url)
                if resp.status_code != 200 or len(resp.text) < 10:
                    continue
                body_lower = resp.text[:500].lower()
                if "<title>404" in body_lower or "not found" in body_lower[:100]:
                    continue
                logger.warning("发现泄露路径: %s [%d bytes]", leak_path, len(resp.text))
                ep = self._add_endpoint(leak_path, HttpMethod.GET)
                ep.auth_required = False
                ep.description = f"信息泄露: {leak_path}"
            except Exception:
                continue

    def _assign_priorities(self) -> None:
        """根据端点特征分配测试优先级"""
        for key, ep in self._endpoints.items():
            if not ep.auth_required:
                ep.priority = Priority.P0
            elif any(p.location in ("query", "body") for p in ep.parameters):
                ep.priority = Priority.P1
            elif re.search(r"\{.*id.*\}|[?&].*id=", ep.path, re.IGNORECASE):
                ep.priority = Priority.P2
            elif re.search(r"upload|file|import|export|download", ep.path, re.IGNORECASE):
                ep.priority = Priority.P3
            else:
                ep.priority = Priority.P4

    def _add_endpoint(self, path: str, method: HttpMethod) -> Endpoint:
        key = f"{method.value}:{path}"
        if key not in self._endpoints:
            self._endpoints[key] = Endpoint(path=path, method=method)
        return self._endpoints[key]
