"""
Reflector — 失败归因与策略纠偏
==============================
借鉴LingXi的L1-L4分级失败归因机制:
  L1 - 工具使用错误（参数错/工具选错）
  L2 - 信息不足（侦察不充分）
  L3 - 策略方向错误（攻击向量选错）
  L4 - 认知偏差（重复失败/忽视线索）

在连续失败时自动触发，防止重复犯错。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class FailureLevel(str, Enum):
    L1 = "L1-工具错误"
    L2 = "L2-信息不足"
    L3 = "L3-策略错误"
    L4 = "L4-认知偏差"


@dataclass
class Reflection:
    level: FailureLevel
    root_cause: str
    missed_clues: list[str] = field(default_factory=list)
    suggestions: list[str] = field(default_factory=list)
    should_switch_strategy: bool = False


@dataclass
class ActionRecord:
    endpoint: str
    vuln_type: str
    payload: str
    success: bool
    response_code: int = 0
    error_msg: str = ""


class Reflector:
    """失败归因反思器：分析连续失败原因并给出纠偏建议"""

    def __init__(self, failure_threshold: int = 5) -> None:
        self._history: list[ActionRecord] = []
        self._consecutive_failures: int = 0
        self._failure_threshold = failure_threshold
        self._tried_strategies: dict[str, int] = {}

    def record(self, action: ActionRecord) -> Reflection | None:
        """记录一次操作，连续失败达到阈值时触发反思"""
        self._history.append(action)

        strategy_key = f"{action.vuln_type}:{action.endpoint}"
        self._tried_strategies[strategy_key] = self._tried_strategies.get(strategy_key, 0) + 1

        if action.success:
            self._consecutive_failures = 0
            return None

        self._consecutive_failures += 1
        if self._consecutive_failures >= self._failure_threshold:
            reflection = self._analyze()
            self._consecutive_failures = 0
            return reflection
        return None

    def _analyze(self) -> Reflection:
        """分析最近的失败记录，进行分级归因"""
        recent = self._history[-self._failure_threshold:]

        same_payload = len(set(a.payload for a in recent)) < len(recent) // 2
        same_endpoint = len(set(a.endpoint for a in recent)) == 1
        same_vuln_type = len(set(a.vuln_type for a in recent)) == 1
        all_errors = all(a.response_code >= 400 for a in recent if a.response_code)

        if same_payload and same_endpoint:
            return Reflection(
                level=FailureLevel.L4,
                root_cause="重复使用相同payload攻击同一端点，陷入死循环",
                missed_clues=["响应内容可能包含WAF特征或过滤规则"],
                suggestions=[
                    "立即停止当前攻击路径",
                    "分析响应内容寻找过滤规则",
                    "切换到完全不同的攻击向量",
                ],
                should_switch_strategy=True,
            )

        if same_vuln_type and not same_endpoint:
            return Reflection(
                level=FailureLevel.L3,
                root_cause=f"持续尝试{recent[0].vuln_type}但全部失败，攻击方向可能错误",
                missed_clues=["目标可能不存在此类漏洞", "可能有其他更容易利用的漏洞类型"],
                suggestions=[
                    f"放弃{recent[0].vuln_type}方向",
                    "重新评估目标特征，选择其他漏洞类型",
                    "回到侦察阶段补充信息",
                ],
                should_switch_strategy=True,
            )

        if all_errors:
            return Reflection(
                level=FailureLevel.L1,
                root_cause="所有请求返回错误状态码，可能是参数格式或认证问题",
                missed_clues=["请求格式可能不正确", "可能需要特定的认证头"],
                suggestions=[
                    "检查请求格式是否正确（Content-Type、参数位置）",
                    "尝试添加认证头或Cookie",
                    "检查目标是否存活",
                ],
                should_switch_strategy=False,
            )

        over_tested = [k for k, v in self._tried_strategies.items() if v > 10]
        if over_tested:
            return Reflection(
                level=FailureLevel.L2,
                root_cause="部分端点已过度测试但无结果，可能遗漏了关键信息",
                missed_clues=["可能存在未发现的隐藏端点", "参数可能在其他位置（Header/Cookie）"],
                suggestions=[
                    "扩大侦察范围，寻找新的端点",
                    "检查HTTP Header和Cookie中的参数",
                    "尝试不同的HTTP方法（PUT/DELETE/PATCH）",
                ],
                should_switch_strategy=False,
            )

        return Reflection(
            level=FailureLevel.L2,
            root_cause="连续失败但模式不明确，可能需要更多信息",
            suggestions=["扩大侦察范围", "检查是否有遗漏的攻击面"],
            should_switch_strategy=False,
        )

    @property
    def stats(self) -> dict:
        total = len(self._history)
        success = sum(1 for a in self._history if a.success)
        return {
            "total_actions": total,
            "successes": success,
            "failures": total - success,
            "consecutive_failures": self._consecutive_failures,
            "strategies_tried": len(self._tried_strategies),
        }
