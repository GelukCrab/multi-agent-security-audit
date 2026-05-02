"""
顾问Agent — 卡点纠偏与策略建议
===============================
不常驻，只在主攻手连续失败时由 Reflector 触发。
职责：分析失败原因，给出具体可执行的纠偏建议。
触发条件：L1-L4 全覆盖（原来只有 L3/L4）。
"""

from __future__ import annotations

import logging
from src.core.reflector import Reflection, FailureLevel

logger = logging.getLogger(__name__)

ADVISOR_PROMPT = """你是一名资深渗透测试顾问。主攻手在测试过程中遇到了困难，需要你的纠偏建议。

## 当前状况
- 目标: {target}
- 已发现漏洞数: {vuln_count}
- 连续失败次数: {consecutive_failures}

## 反思器归因结果
- 失败等级: {failure_level}
- 根因: {root_cause}
- 遗漏线索: {missed_clues}
- 初步建议: {current_suggestions}

## 已尝试的攻击路径（最近20条）
{tried_paths}

## 已发现的漏洞
{found_vulns}

请根据失败等级给出针对性建议：

**L1-工具错误**：检查请求格式、参数位置、认证方式，给出正确的调用示例
**L2-信息不足**：指出具体遗漏了哪些侦察步骤，建议用哪些工具补充
**L3-策略错误**：分析为什么当前方向不对，建议切换到哪种漏洞类型，给出理由
**L4-认知偏差**：指出死循环的具体表现，给出完全不同的攻击思路

要求：
1. 简洁直接，不废话
2. 给出具体可执行的下一步操作（工具名+参数示例）
3. 如果有明显遗漏的攻击面，直接点出来"""


class AdvisorAgent:
    """顾问Agent：在主攻手卡住时提供策略纠偏，L1-L4 全覆盖"""

    def __init__(self, llm_provider=None) -> None:
        self._llm = llm_provider
        self._consultations: list[dict] = []

    def consult(
        self,
        reflection: Reflection,
        target: str,
        endpoint_count: int,
        vuln_count: int,
        consecutive_failures: int,
        tried_paths: list[str],
        found_vulns: list[str],
    ) -> str:
        """向顾问请求纠偏建议，L1-L4 全部触发"""
        if not self._llm or not getattr(self._llm, "has_advisor", False):
            advice = self._rule_based_advice(reflection)
            logger.info("顾问[规则-%s]: %s", reflection.level.value, advice[:100])
            return advice

        prompt = ADVISOR_PROMPT.format(
            target=target,
            vuln_count=vuln_count,
            consecutive_failures=consecutive_failures,
            failure_level=reflection.level.value,
            root_cause=reflection.root_cause,
            missed_clues="\n".join(f"- {c}" for c in reflection.missed_clues) or "无",
            current_suggestions="\n".join(f"- {s}" for s in reflection.suggestions) or "无",
            tried_paths="\n".join(f"- {p}" for p in tried_paths[-20:]) or "无",
            found_vulns="\n".join(f"- {v}" for v in found_vulns) or "无",
        )

        logger.info("===== 顾问介入 [%s] =====", reflection.level.value)
        logger.info("触发原因: %s", reflection.root_cause)

        advice = self._llm.chat(
            [{"role": "user", "content": prompt}],
            role="advisor",
        )

        if not advice:
            advice = self._rule_based_advice(reflection)
            logger.info("顾问LLM无响应，使用规则建议")
        else:
            logger.info("顾问建议:\n%s", advice[:600])

        self._consultations.append({
            "failure_level": reflection.level.value,
            "root_cause": reflection.root_cause,
            "advice": advice[:500],
        })
        return advice

    def _rule_based_advice(self, reflection: Reflection) -> str:
        """无 LLM 时的规则化建议，覆盖 L1-L4"""
        if reflection.level == FailureLevel.L4:
            return (
                "检测到死循环。立即停止当前攻击路径，切换到完全不同的漏洞类型。\n"
                "建议：如果一直在测 SQL 注入，改测文件上传或命令注入；"
                "如果一直在测 Web，先用 port_scan 看看有没有其他服务。"
            )
        if reflection.level == FailureLevel.L3:
            return (
                "攻击方向可能错误。建议回到侦察阶段重新分析目标特征。\n"
                "建议：用 dir_fuzz 爆破目录，用 analyze_js 分析 JS 文件，"
                "寻找其他攻击面。检查是否有遗漏的端点或参数。"
            )
        if reflection.level == FailureLevel.L1:
            return (
                "请求格式可能有问题。检查以下几点：\n"
                "1. Content-Type 是否正确（form 用 application/x-www-form-urlencoded）\n"
                "2. 是否需要先 login 获取 Cookie 再操作\n"
                "3. 参数是否在正确位置（URL/Body/Header）\n"
                "4. 目标服务是否存活（用 fetch_page 验证）"
            )
        # L2
        return (
            "信息可能不足。扩大侦察范围：\n"
            "1. dir_fuzz 爆破目录（用 big 字典）\n"
            "2. analyze_js 分析页面 JS 提取 API 端点\n"
            "3. 检查 HTTP Header 和 Cookie 中的参数\n"
            "4. 尝试不同 HTTP 方法（PUT/DELETE/OPTIONS）"
        )

    @property
    def consultation_count(self) -> int:
        return len(self._consultations)

    @property
    def history(self) -> list[dict]:
        return list(self._consultations)
