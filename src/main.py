"""入口"""

from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import warnings

import yaml

from src.core.orchestrator import Orchestrator
from src.utils.display import print_banner, print_endpoints_table, print_vulns_table, console

warnings.filterwarnings("ignore", message=".*Unverified HTTPS.*")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    datefmt="%H:%M:%S",
)


def load_config(config_path: str, target: str | None = None, proxy: str | None = None) -> dict:
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)
    if target:
        config["target"]["url"] = target
    if proxy:
        config["target"]["proxy"] = proxy
    return config


def main() -> None:
    parser = argparse.ArgumentParser(description="多Agent协作安全审计框架")
    parser.add_argument("--target", "-t", required=True, help="目标URL")
    parser.add_argument("--config", "-c", default="config/default.yaml", help="配置文件路径")
    parser.add_argument("--proxy", "-p", default="", help="代理地址")
    parser.add_argument("--format", "-f", choices=["json", "markdown"], default="json", help="报告格式")
    parser.add_argument("--output", "-o", default="./reports", help="报告输出目录")
    parser.add_argument("--verbose", "-v", action="store_true", help="详细日志")
    parser.add_argument("--no-ai", action="store_true", help="不使用AI模型，纯规则引擎模式")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    config = load_config(args.config, target=args.target, proxy=args.proxy)
    config["report"]["format"] = args.format
    config["report"]["output_dir"] = args.output
    config["use_ai"] = not args.no_ai

    print_banner()
    orchestrator = Orchestrator(config)
    report = asyncio.run(orchestrator.run())

    console.print()
    print_vulns_table(report.get("vulnerabilities", []))
    console.print()
    print_endpoints_table(report.get("endpoints", []))
    console.print()

    summary = report.get("summary", {})
    console.print(f"[bold]端点总数:[/bold] {summary.get('total_endpoints', 0)}")
    console.print(f"[bold]已测试:[/bold] {summary.get('tested', 0)}")
    console.print(f"[bold]发现漏洞:[/bold] [red]{summary.get('vulnerable', 0)}[/red]")
    console.print(f"[bold]覆盖率:[/bold] {summary.get('coverage', '0%')}")
    console.print()


if __name__ == "__main__":
    main()
