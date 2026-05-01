"""
顾问Agent — 卡点纠偏与策略建议
===============================
不常驻，只在主攻手连续失败时由Reflector触发。
职责: 分析失败原因，建议新的攻击方向。
"""

from __future__ import annotations

import logging
from src.core.reflector import Reflection, FailureLevel

logger = logging.getLogger(__name__)

ADVISOR_PROMPT = """你是一名资深渗透测试顾问。主攻手在测试过程中遇到了困难，需要你的纠偏建议。

## 当前状况
- 目标: {target}
- 已发现端点数: {endpoint_count}
- 已发现漏洞数: {vuln_count}
- 连续失败次数: {consecutive_failures}

## 反思器分析
- 失败等级: {failure_level}
- 根因: {root_cause}
- 遗漏线索: {missed_clues}
- 当前建议: {current_suggestions}

## 已尝试的攻击路径
{tried_paths}

## 已发现的漏洞
{found_vulns}

请给出具体的纠偏建议:
1. 分析主攻手为什么卡住了
2. 建议接下来应该尝试什么方向
3. 给出具体的测试步骤或payload

要求简洁直接，不要废话，直接给可执行的建议。"""


class AdvisorAgent:
    """顾问Agent: 在主攻手卡住时提供策略纠偏"""

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
        """向顾问请求纠偏建议"""
        if not self._llm or not self._llm.has_advisor:
            return self._rule_based_advice(reflection)

        prompt = ADVISOR_PROMPT.format(
            target=target,
            endpoint_count=endpoint_count,
            vuln_count=vuln_count,
            consecutive_failures=consecutive_failures,
            failure_level=reflection.level.value,
            root_cause=reflection.root_cause,
            missed_clues="\n".join(f"- {c}" for c in reflection.missed_clues) or "无",
            current_suggestions="\n".join(f"- {s}" for s in reflection.suggestions) or "无",
            tried_paths="\n".join(f"- {p}" for p in tried_paths[-20:]) or "无",
            found_vulns="\n".join(f"- {v}" for v in found_vulns) or "无",
        )

        logger.info("===== 顾问Agent介入 [%s] =====", reflection.level.value)
        logger.info("触发原因: %s", reflection.root_cause)
        advice = self._llm.chat(
            [{"role": "user", "content": prompt}],
            role="advisor",
        )

        if advice:
            self._consultations.append({
                "failure_level": reflection.level.value,
                "root_cause": reflection.root_cause,
                "advice": advice[:500],
            })
            logger.info("顾问建议:\n%s", advice[:800])
        else:
            advice = self._rule_based_advice(reflection)
            logger.info("顾问LLM无响应，使用规则建议")

        return advice

    def _rule_based_advice(self, reflection: Reflection) -> str:
        """无AI时的规则化建议"""
        if reflection.level == FailureLevel.L4:
            return ("检测到死循环。立即停止当前攻击路径，"
                    "切换到完全不同的漏洞类型。"
                    "如果一直在测SQL注入，改测文件上传或SSTI。")
        if reflection.level == FailureLevel.L3:
            return ("攻击方向可能错误。建议回到侦察阶段，"
                    "重新分析目标特征，寻找其他攻击面。"
                    "检查是否有遗漏的端点或参数。")
        if reflection.level == FailureLevel.L1:
            return ("请求格式可能有问题。检查Content-Type、"
                    "参数位置(query/body/header)、认证头。"
                    "确认目标服务是否存活。")
        return ("信息可能不足。扩大侦察范围，"
                "尝试不同HTTP方法，检查Header和Cookie参数。")

    @property
    def consultation_count(self) -> int:
        return len(self._consultations)

    @property
    def history(self) -> list[dict]:
        return list(self._consultations)
