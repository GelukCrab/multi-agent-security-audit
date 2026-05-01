"""控制台美化输出"""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

console = Console()


def print_banner() -> None:
    banner = Text()
    banner.append("Multi-Agent Security Audit Framework\n", style="bold cyan")
    banner.append("多Agent协作安全审计框架 v0.1.0", style="dim")
    console.print(Panel(banner, border_style="cyan"))


def print_endpoints_table(endpoints: list[dict]) -> None:
    table = Table(title="端点清单", show_lines=True)
    table.add_column("序号", style="dim", width=4)
    table.add_column("路径", style="cyan")
    table.add_column("方法", style="green", width=6)
    table.add_column("优先级", width=12)
    table.add_column("状态", width=10)

    for i, ep in enumerate(endpoints, 1):
        status = ep["status"]
        if "漏洞" in status:
            style = "bold red"
        elif "安全" in status:
            style = "green"
        else:
            style = "yellow"
        table.add_row(str(i), ep["path"], ep["method"], ep["priority"], Text(status, style=style))

    console.print(table)


def print_vulns_table(vulns: list[dict]) -> None:
    if not vulns:
        console.print("[green]未发现漏洞[/green]")
        return

    table = Table(title="漏洞列表", show_lines=True, border_style="red")
    table.add_column("类型", style="bold red")
    table.add_column("端点", style="cyan")
    table.add_column("参数", style="yellow")
    table.add_column("严重程度")
    table.add_column("描述")

    for v in vulns:
        severity = v["severity"]
        if severity == "严重":
            sev_style = "bold red"
        elif severity == "高":
            sev_style = "red"
        elif severity == "中":
            sev_style = "yellow"
        else:
            sev_style = "dim"
        table.add_row(
            v["vuln_type"], v["endpoint"], v["parameter"],
            Text(severity, style=sev_style), v["description"],
        )

    console.print(table)
