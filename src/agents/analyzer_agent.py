"""分析Agent — 威胁建模与测试计划生成"""

from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass, field

from src.core import (
    Endpoint, VulnType, Priority, TestStatus, AgentMessage,
)
from src.core.message_bus import MessageBus

logger = logging.getLogger(__name__)

THREAT_MODEL_PROMPT = """你是一名资深安全审计专家。根据以下API端点信息，分析每个端点可能存在的漏洞类型。

端点列表:
{endpoints_json}

对每个端点，输出JSON数组，每项包含:
- path: 端点路径
- method: HTTP方法
- threats: 可能的漏洞类型列表(从以下选择: SQL注入/水平越权/垂直越权/未授权访问/模板注入/远程命令执行/文件上传/信息泄露/逻辑漏洞/SSRF/XSS)
- risk_score: 风险评分(0-1)
- reasoning: 推理依据(一句话)

只输出JSON数组，不要其他内容。"""

VULN_TYPE_MAP = {
    "SQL注入": VulnType.SQLI,
    "水平越权": VulnType.IDOR,
    "垂直越权": VulnType.VERTICAL_AUTHZ,
    "未授权访问": VulnType.UNAUTH,
    "模板注入": VulnType.SSTI,
    "远程命令执行": VulnType.RCE,
    "文件上传": VulnType.FILE_UPLOAD,
    "信息泄露": VulnType.INFO_LEAK,
    "逻辑漏洞": VulnType.LOGIC,
    "SSRF": VulnType.SSRF,
    "XSS": VulnType.XSS,
}


@dataclass
class TestCase:
    endpoint: Endpoint
    vuln_type: VulnType
    risk_score: float
    reasoning: str


class AnalyzerAgent:
    """威胁建模Agent：基于AI长链推理分析每个端点的潜在漏洞"""

    def __init__(
        self, bus: MessageBus, llm_provider=None,
        risk_threshold: float = 0.3,
    ) -> None:
        self.bus = bus
        self._llm = llm_provider
        self.risk_threshold = risk_threshold
        self._test_plan: list[TestCase] = []

        self.bus.subscribe("endpoints", self._on_endpoints)
        self.bus.subscribe("result", self._on_result)

    async def _on_endpoints(self, msg: AgentMessage) -> None:
        endpoints: list[Endpoint] = msg.payload
        logger.info("收到 %d 个端点，开始威胁建模...", len(endpoints))
        self._test_plan = await self._generate_test_plan(endpoints)
        logger.info("生成 %d 个测试用例", len(self._test_plan))

        await self.bus.publish(AgentMessage(
            sender="analyzer", receiver="exploit",
            msg_type="test_plan", payload=self._test_plan,
        ))

    async def _on_result(self, msg: AgentMessage) -> None:
        result = msg.payload
        if result.get("found_vuln"):
            logger.info("发现漏洞类型 %s，扩大同类端点测试深度", result["vuln_type"])

    async def _generate_test_plan(self, endpoints: list[Endpoint]) -> list[TestCase]:
        if not self._llm:
            logger.info("使用规则引擎生成测试计划")
            return self._rule_based_fallback(endpoints)

        endpoints_data = [
            {
                "path": ep.path,
                "method": ep.method.value,
                "parameters": [{"name": p.name, "location": p.location} for p in ep.parameters],
                "auth_required": ep.auth_required,
                "description": ep.description,
            }
            for ep in endpoints
        ]

        logger.info("调用主攻手模型进行威胁建模...")
        analysis = self._llm.chat_json(
            [{"role": "user", "content": THREAT_MODEL_PROMPT.format(
                endpoints_json=json.dumps(endpoints_data, ensure_ascii=False)
            )}],
            role="main",
        )

        if not analysis or not isinstance(analysis, list):
            logger.warning("AI响应解析失败，回退到规则引擎")
            return self._rule_based_fallback(endpoints)

        test_cases = []
        ep_map = {f"{ep.method.value}:{ep.path}": ep for ep in endpoints}

        for item in analysis:
            if not isinstance(item, dict):
                continue
            key = f"{item.get('method', '')}:{item.get('path', '')}"
            ep = ep_map.get(key)
            if not ep or item.get("risk_score", 0) < self.risk_threshold:
                continue
            for threat_name in item.get("threats", []):
                vtype = VULN_TYPE_MAP.get(threat_name)
                if vtype:
                    test_cases.append(TestCase(
                        endpoint=ep, vuln_type=vtype,
                        risk_score=item["risk_score"],
                        reasoning=item.get("reasoning", ""),
                    ))

        test_cases.sort(key=lambda tc: tc.risk_score, reverse=True)
        logger.info("AI威胁建模完成，生成 %d 个测试用例", len(test_cases))
        return test_cases

    def _rule_based_fallback(self, endpoints: list[Endpoint]) -> list[TestCase]:
        cases = []
        for ep in endpoints:
            if not ep.auth_required:
                cases.append(TestCase(ep, VulnType.UNAUTH, 0.9, "无需认证"))
                cases.append(TestCase(ep, VulnType.INFO_LEAK, 0.8, "无需认证可能泄露信息"))
            if any("id" in p.name.lower() for p in ep.parameters):
                cases.append(TestCase(ep, VulnType.IDOR, 0.7, "含ID参数"))
                cases.append(TestCase(ep, VulnType.SQLI, 0.6, "ID参数可能拼接"))
            if any(p.location in ("query", "body") for p in ep.parameters):
                cases.append(TestCase(ep, VulnType.SQLI, 0.5, "用户输入参数"))
                cases.append(TestCase(ep, VulnType.XSS, 0.4, "参数可能回显"))
                cases.append(TestCase(ep, VulnType.SSTI, 0.3, "参数可能进入模板"))
            if re.search(r"upload|file|import|attach", ep.path, re.IGNORECASE):
                cases.append(TestCase(ep, VulnType.FILE_UPLOAD, 0.7, "文件操作相关"))
            if re.search(r"exec|run|cmd|ping|shell|system", ep.path, re.IGNORECASE):
                cases.append(TestCase(ep, VulnType.RCE, 0.8, "命令执行相关"))
            if re.search(r"url|webhook|callback|proxy|fetch|request", ep.path, re.IGNORECASE):
                cases.append(TestCase(ep, VulnType.SSRF, 0.6, "URL相关参数"))
        cases.sort(key=lambda tc: tc.risk_score, reverse=True)
        return cases
