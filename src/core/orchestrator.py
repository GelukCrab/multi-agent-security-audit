"""多Agent调度协调器"""

from __future__ import annotations

import logging

from src.llm import create_provider_from_config
from src.core.reflector import Reflector
from src.core.memory import MemoryStore
from src.core.skill_registry import SkillRegistry
from src.utils.http_client import HttpClient
from src.agents.pentest_agent import PentestAgent
from src.agents.advisor_agent import AdvisorAgent
from src.core.report import ReportGenerator
from src.tools import pentest_tools

logger = logging.getLogger(__name__)


class Orchestrator:
    """调度器：驱动LLM主攻手完成渗透测试"""

    def __init__(self, config: dict) -> None:
        self.config = config
        target = config["target"]

        self.client = HttpClient(
            proxy=target.get("proxy", ""),
            timeout=target.get("timeout", 15),
        )
        self.reflector = Reflector(
            failure_threshold=config.get("reflector_threshold", 5),
        )
        self.memory = MemoryStore()
        self.skills = SkillRegistry()
        self.skills.load()

        llm_provider = None
        if config.get("use_ai", True):
            llm_provider = create_provider_from_config(config)

        if not llm_provider:
            raise RuntimeError("AI模式需要配置LLM API key")

        self.advisor = AdvisorAgent(llm_provider=llm_provider)

        agent_cfg = config.get("agents", {}).get("pentest", {})
        self.agent = PentestAgent(
            llm=llm_provider,
            client=self.client,
            reflector=self.reflector,
            memory=self.memory,
            advisor=self.advisor,
            max_rounds=agent_cfg.get("max_rounds", 30),
        )

    async def run(self) -> dict:
        target_url = self.config["target"]["url"]

        logger.info("=" * 60)
        logger.info("AI渗透测试启动")
        logger.info("目标: %s", target_url)
        logger.info("=" * 60)

        self.memory.start_audit(target_url)

        findings = await self.agent.run(target_url)

        await self.client.close()

        for f in findings:
            self.memory.record_success(
                f["endpoint"], f["vuln_type"], f["poc"])
        self.memory.save_experience()

        report_cfg = self.config.get("report", {})
        generator = ReportGenerator(
            output_format=report_cfg.get("format", "json"),
            output_dir=report_cfg.get("output_dir", "./reports"),
        )

        report = generator.generate_from_findings(
            target=target_url,
            findings=findings,
        )

        stats = self.reflector.stats
        logger.info("=" * 60)
        logger.info("渗透测试完成")
        logger.info("发现漏洞: %d", len(findings))
        logger.info("HTTP请求: %d (成功%d/失败%d)",
                    stats["total_actions"], stats["successes"], stats["failures"])
        logger.info("顾问介入: %d 次", self.advisor.consultation_count)
        logger.info("=" * 60)

        return report
