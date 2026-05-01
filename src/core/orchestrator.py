"""多Agent调度协调器"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import asdict

from src.core import Endpoint, Vulnerability
from src.core.message_bus import MessageBus
from src.core.skill_registry import SkillRegistry
from src.core.reflector import Reflector
from src.core.memory import MemoryStore
from src.llm import create_provider_from_config
from src.utils.http_client import HttpClient
from src.agents.recon_agent import ReconAgent
from src.agents.analyzer_agent import AnalyzerAgent
from src.agents.exploit_agent import ExploitAgent
from src.agents.advisor_agent import AdvisorAgent
from src.core.report import ReportGenerator

logger = logging.getLogger(__name__)


class Orchestrator:
    """调度器：协调三个Agent的生命周期和通信"""

    def __init__(self, config: dict) -> None:
        self.config = config
        self.bus = MessageBus()
        target = config["target"]

        self.client = HttpClient(
            proxy=target.get("proxy", ""),
            timeout=target.get("timeout", 15),
        )

        self.skills = SkillRegistry()
        self.skills.load()

        self.reflector = Reflector(
            failure_threshold=config.get("reflector_threshold", 5),
        )
        self.memory = MemoryStore()

        llm_provider = None
        if config.get("use_ai", True):
            llm_provider = create_provider_from_config(config)

        agent_cfg = config.get("agents", {})
        self.recon = ReconAgent(
            base_url=target["url"],
            client=self.client,
            bus=self.bus,
            js_crawl_depth=agent_cfg.get("recon", {}).get("js_crawl_depth", 3),
            parse_swagger=agent_cfg.get("recon", {}).get("parse_swagger", True),
        )
        self.analyzer = AnalyzerAgent(
            bus=self.bus,
            llm_provider=llm_provider,
            risk_threshold=agent_cfg.get("analyzer", {}).get("risk_threshold", 0.3),
        )
        self.advisor = AdvisorAgent(llm_provider=llm_provider)
        self.exploit = ExploitAgent(
            base_url=target["url"],
            client=self.client,
            bus=self.bus,
            max_cases=agent_cfg.get("exploit", {}).get("max_cases_per_endpoint", 20),
            time_threshold=agent_cfg.get("exploit", {}).get("time_threshold", 3.0),
            reflector=self.reflector,
            memory=self.memory,
            advisor=self.advisor,
        )

    async def run(self) -> dict:
        target_url = self.config["target"]["url"]

        logger.info("=" * 60)
        logger.info("多Agent安全审计启动")
        logger.info("目标: %s", target_url)
        logger.info("已加载技能: %s", [s.meta.name for s in self.skills.all()])
        logger.info("AI模式: %s", "启用" if self.config.get("use_ai") else "规则引擎")
        logger.info("=" * 60)

        self.memory.start_audit(target_url)

        experience = self.memory.load_experience(target_url)
        if experience:
            logger.info("发现历史经验: %d个已知漏洞, %d条死胡同",
                        len(experience.known_vulns), len(experience.dead_ends))

        endpoints = await self.recon.run()

        if self.memory.current:
            self.memory.current.endpoints_found = len(endpoints)

        await self.client.close()
        self.memory.save_experience()

        report_cfg = self.config.get("report", {})
        generator = ReportGenerator(
            output_format=report_cfg.get("format", "json"),
            output_dir=report_cfg.get("output_dir", "./reports"),
        )

        report = generator.generate(
            target=target_url,
            endpoints=endpoints,
            vulnerabilities=self.exploit.results,
            message_history=self.bus.history,
        )

        stats = self.reflector.stats
        logger.info("=" * 60)
        logger.info("审计完成")
        logger.info("端点总数: %d", len(endpoints))
        logger.info("发现漏洞: %d", len(self.exploit.results))
        logger.info("测试动作: %d (成功%d/失败%d)",
                    stats["total_actions"], stats["successes"], stats["failures"])
        logger.info("顾问介入: %d 次", self.advisor.consultation_count)
        logger.info("=" * 60)

        return report
