"""使用示例：对目标执行安全审计"""

import asyncio
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.message_bus import MessageBus
from src.utils.http_client import HttpClient
from src.agents.recon_agent import ReconAgent
from src.agents.analyzer_agent import AnalyzerAgent
from src.agents.exploit_agent import ExploitAgent
from src.core.report import ReportGenerator


async def main():
    target = "https://httpbin.org"

    bus = MessageBus()
    client = HttpClient(timeout=10)

    recon = ReconAgent(base_url=target, client=client, bus=bus)
    analyzer = AnalyzerAgent(bus=bus, use_ai=False)
    exploit = ExploitAgent(base_url=target, client=client, bus=bus)

    endpoints = await recon.run()

    await client.close()

    generator = ReportGenerator(output_format="json", output_dir="./reports")
    report = generator.generate(
        target=target,
        endpoints=endpoints,
        vulnerabilities=exploit.results,
        message_history=bus.history,
    )

    print(f"\n端点总数: {report['summary']['total_endpoints']}")
    print(f"已测试: {report['summary']['tested']}")
    print(f"发现漏洞: {report['summary']['vulnerable']}")
    print(f"覆盖率: {report['summary']['coverage']}")


if __name__ == "__main__":
    asyncio.run(main())
