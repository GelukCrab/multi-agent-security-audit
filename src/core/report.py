"""报告生成器"""

from __future__ import annotations

import json
import os
import logging
from datetime import datetime
from dataclasses import asdict

from src.core import Endpoint, Vulnerability, TestStatus, AgentMessage

logger = logging.getLogger(__name__)


class ReportGenerator:

    def __init__(self, output_format: str = "json", output_dir: str = "./reports") -> None:
        self.output_format = output_format
        self.output_dir = output_dir

    def generate(
        self,
        target: str,
        endpoints: list[Endpoint],
        vulnerabilities: list[Vulnerability],
        message_history: list[AgentMessage],
    ) -> dict:
        total = len(endpoints)
        tested = sum(1 for ep in endpoints if ep.test_status != TestStatus.PENDING)
        vuln_count = sum(1 for ep in endpoints if ep.test_status == TestStatus.VULNERABLE)
        safe_count = sum(1 for ep in endpoints if ep.test_status == TestStatus.SAFE)
        coverage = (tested / total * 100) if total > 0 else 0

        report = {
            "target": target,
            "scan_time": datetime.now().isoformat(),
            "summary": {
                "total_endpoints": total,
                "tested": tested,
                "vulnerable": vuln_count,
                "safe": safe_count,
                "coverage": f"{coverage:.1f}%",
            },
            "vulnerabilities": [asdict(v) for v in vulnerabilities],
            "endpoints": [
                {
                    "path": ep.path,
                    "method": ep.method.value,
                    "priority": ep.priority.value,
                    "status": ep.test_status.value,
                    "auth_required": ep.auth_required,
                }
                for ep in endpoints
            ],
        }

        os.makedirs(self.output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = "md" if self.output_format == "markdown" else self.output_format
        filename = f"audit_{timestamp}.{ext}"
        filepath = os.path.join(self.output_dir, filename)

        if self.output_format == "json":
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
        elif self.output_format == "markdown":
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(self._to_markdown(report))

        logger.info("报告已保存: %s", filepath)
        return report

    def generate_from_findings(self, target: str, findings: list[dict]) -> dict:
        """从PentestAgent的findings生成报告"""
        report = {
            "target": target,
            "scan_time": datetime.now().isoformat(),
            "summary": {
                "total_findings": len(findings),
                "critical": sum(1 for f in findings if f.get("severity") == "严重"),
                "high": sum(1 for f in findings if f.get("severity") == "高"),
                "medium": sum(1 for f in findings if f.get("severity") == "中"),
                "low": sum(1 for f in findings if f.get("severity") == "低"),
            },
            "vulnerabilities": findings,
        }

        os.makedirs(self.output_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        ext = "md" if self.output_format == "markdown" else self.output_format
        filename = f"audit_{timestamp}.{ext}"
        filepath = os.path.join(self.output_dir, filename)

        if self.output_format == "json":
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
        elif self.output_format == "markdown":
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(self._to_markdown(report))

        logger.info("报告已保存: %s", filepath)
        return report

    def _to_markdown(self, report: dict) -> str:
        lines = [
            f"# 安全审计报告",
            f"",
            f"**目标**: {report['target']}",
            f"**时间**: {report['scan_time']}",
            f"",
            f"## 概览",
            f"| 指标 | 数值 |",
            f"|------|------|",
        ]
        for k, v in report["summary"].items():
            lines.append(f"| {k} | {v} |")

        lines.append("")
        lines.append("## 漏洞详情")
        lines.append("")
        for v in report["vulnerabilities"]:
            lines.append(f"### {v.get('vuln_type', 'Unknown')} — {v.get('endpoint', '')}")
            lines.append(f"- 严重程度: {v.get('severity', '')}")
            lines.append(f"- 参数: {v.get('parameter', '')}")
            lines.append(f"- 描述: {v.get('description', '')}")
            lines.append(f"- PoC: `{v.get('poc', '')}`")
            if v.get("evidence"):
                lines.append(f"- 证据: `{v['evidence'][:200]}`")
            lines.append("")

        if "endpoints" in report:
            lines.append("## 端点清单")
            lines.append("")
            lines.append("| 路径 | 方法 | 优先级 | 状态 |")
            lines.append("|------|------|--------|------|")
            for ep in report["endpoints"]:
                lines.append(f"| {ep['path']} | {ep['method']} | {ep['priority']} | {ep['status']} |")

        return "\n".join(lines)
