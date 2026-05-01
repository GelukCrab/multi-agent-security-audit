"""入口"""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import sys
import warnings
from datetime import datetime

import yaml

from src.core.orchestrator import Orchestrator


def _load_dotenv() -> None:
    """加载项目根目录的.env文件"""
    env_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), ".env")
    if not os.path.exists(env_path):
        return
    with open(env_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, val = line.split("=", 1)
            os.environ.setdefault(key.strip(), val.strip())


_load_dotenv()
from src.utils.display import print_banner, print_endpoints_table, print_vulns_table, console

warnings.filterwarnings("ignore", message=".*Unverified HTTPS.*")


def setup_logging(verbose: bool, log_dir: str = "logs") -> str:
    """配置日志：控制台 + 文件双输出"""
    os.makedirs(log_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = os.path.join(log_dir, f"audit_{timestamp}.log")

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG if verbose else logging.INFO)
    console_handler.setFormatter(fmt)

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        "%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))

    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)

    return log_file


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
    parser.add_argument("--format", "-f", choices=["json", "markdown"], default=None, help="报告格式")
    parser.add_argument("--output", "-o", default="./reports", help="报告输出目录")
    parser.add_argument("--verbose", "-v", action="store_true", help="详细日志")
    parser.add_argument("--no-ai", action="store_true", help="不使用AI模型，纯规则引擎模式")
    parser.add_argument("--log-dir", default="./logs", help="日志输出目录")
    args = parser.parse_args()

    log_file = setup_logging(args.verbose, args.log_dir)
    logger = logging.getLogger("main")
    logger.info("日志文件: %s", log_file)

    config = load_config(args.config, target=args.target, proxy=args.proxy)
    if args.format:
        config["report"]["format"] = args.format
    config["report"]["output_dir"] = args.output
    config["use_ai"] = not args.no_ai

    print_banner()

    if args.no_ai:
        console.print("[red]当前架构需要AI模型驱动，--no-ai模式暂不支持[/red]")
        return

    orchestrator = Orchestrator(config)
    report = asyncio.run(orchestrator.run())

    console.print()
    print_vulns_table(report.get("vulnerabilities", []))
    console.print()

    summary = report.get("summary", {})
    console.print(f"[bold]发现漏洞:[/bold] [red]{summary.get('total_findings', 0)}[/red]")
    console.print(f"  严重: {summary.get('critical', 0)} | 高: {summary.get('high', 0)} | 中: {summary.get('medium', 0)} | 低: {summary.get('low', 0)}")
    console.print(f"[dim]日志文件: {log_file}[/dim]")
    console.print()


if __name__ == "__main__":
    main()
