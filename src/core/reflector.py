"""
Reflector — 失败归因与策略纠偏
==============================
L1-L4 分级失败归因机制:
  L1 - 工具使用错误（参数错/工具选错/请求格式错）
  L2 - 信息不足（侦察不充分/遗漏攻击面）
  L3 - 策略方向错误（攻击向量选错/目标无此漏洞）
  L4 - 认知偏差（重复失败/死循环/忽视线索）

归因分两层：
  1. 规则层：快速判断明显模式（死循环/全4xx等）
  2. LLM层：复用顾问模型对模糊情况做深度归因

在连续失败时自动触发，防止重复犯错。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

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
    response_body: str = ""  # 响应体摘要，用于 LLM 归因


# LLM 归因 prompt，复用顾问模型
_LLM_ANALYZE_PROMPT = """你是渗透测试反思器，负责对失败的攻击操作进行根因分析。

## 最近 {n} 次失败操作
{history}

## 已尝试的攻击策略统计
{strategies}

请分析失败原因，输出 JSON：
{{
  "level": "L1-工具错误|L2-信息不足|L3-策略错误|L4-认知偏差",
  "root_cause": "一句话说明根本原因",
  "missed_clues": ["可能遗漏的线索1", "线索2"],
  "suggestions": ["具体建议1", "建议2", "建议3"],
  "should_switch_strategy": true/false
}}

判断标准：
- L1：请求格式错/参数位置错/认证缺失/工具调用参数有误
- L2：侦察不充分/遗漏端点/未分析JS/未爆破目录
- L3：攻击方向选错/目标可能无此漏洞/需要换漏洞类型
- L4：重复相同操作/陷入死循环/明显忽视了响应中的线索

只输出 JSON，不要其他内容。"""


class Reflector:
    """失败归因反思器：规则层 + LLM层双重归因"""

    def __init__(self, failure_threshold: int = 5, llm_provider=None) -> None:
        self._history: list[ActionRecord] = []
        self._consecutive_failures: int = 0
        self._failure_threshold = failure_threshold
        self._tried_strategies: dict[str, int] = {}
        self._llm = llm_provider  # 复用顾问模型做 LLM 归因

    def set_llm(self, llm_provider) -> None:
        """延迟注入 LLM（避免循环依赖）"""
        self._llm = llm_provider

    def record(self, action: ActionRecord) -> Reflection | None:
        """记录一次操作，连续失败达到阈值时触发反思"""
        self._history.append(action)

        strategy_key = f"{action.vuln_type}:{action.endpoint}"
        self._tried_strategies[strategy_key] = (
            self._tried_strategies.get(strategy_key, 0) + 1
        )

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
        """两层归因：规则层快速判断，LLM层深度分析"""
        recent = self._history[-self._failure_threshold:]

        # ── 规则层：明显模式直接判断 ──────────────────────────────────────
        same_payload   = len(set(a.payload for a in recent)) < max(len(recent) // 2, 1)
        same_endpoint  = len(set(a.endpoint for a in recent)) == 1
        same_vuln_type = len(set(a.vuln_type for a in recent)) == 1
        all_errors     = all(a.response_code >= 400 for a in recent if a.response_code)
        has_error_msg  = any(a.error_msg for a in recent)

        # L4：死循环（相同 payload + 相同端点）
        if same_payload and same_endpoint:
            r = Reflection(
                level=FailureLevel.L4,
                root_cause="重复使用相同 payload 攻击同一端点，陷入死循环",
                missed_clues=["响应内容可能包含 WAF 特征或过滤规则", "可能需要编码绕过"],
                suggestions=[
                    "立即停止当前攻击路径",
                    "分析响应内容寻找过滤规则",
                    "切换到完全不同的攻击向量",
                ],
                should_switch_strategy=True,
            )
            logger.warning("反思[规则-L4]: %s", r.root_cause)
            return r

        # L1：全部请求报错（工具/格式问题）
        if all_errors or has_error_msg:
            r = Reflection(
                level=FailureLevel.L1,
                root_cause="所有请求返回错误，可能是参数格式、认证或工具调用问题",
                missed_clues=["请求格式可能不正确", "可能需要认证头或 Cookie"],
                suggestions=[
                    "检查请求格式（Content-Type、参数位置）",
                    "先用 login 工具获取会话再操作",
                    "确认目标服务是否存活",
                ],
                should_switch_strategy=False,
            )
            logger.warning("反思[规则-L1]: %s", r.root_cause)
            return r

        # ── LLM 层：模糊情况交给顾问模型深度分析 ─────────────────────────
        if self._llm and getattr(self._llm, "has_advisor", False):
            r = self._llm_analyze(recent)
            if r:
                logger.warning("反思[LLM-%s]: %s", r.level.value, r.root_cause)
                return r

        # ── 兜底规则 ──────────────────────────────────────────────────────
        if same_vuln_type:
            r = Reflection(
                level=FailureLevel.L3,
                root_cause=f"持续尝试 {recent[0].vuln_type} 但全部失败，攻击方向可能错误",
                missed_clues=["目标可能不存在此类漏洞", "可能有其他更容易利用的漏洞类型"],
                suggestions=[
                    f"放弃 {recent[0].vuln_type} 方向",
                    "重新评估目标特征，选择其他漏洞类型",
                    "回到侦察阶段补充信息",
                ],
                should_switch_strategy=True,
            )
        else:
            over_tested = [k for k, v in self._tried_strategies.items() if v > 8]
            r = Reflection(
                level=FailureLevel.L2,
                root_cause="连续失败，可能遗漏了关键攻击面或信息",
                missed_clues=["可能存在未发现的隐藏端点", "参数可能在 Header/Cookie 中"],
                suggestions=[
                    "扩大侦察范围：dir_fuzz 爆破目录、analyze_js 分析 JS",
                    "检查 HTTP Header 和 Cookie 中的参数",
                    "尝试不同的 HTTP 方法（PUT/DELETE/PATCH）",
                ] + ([f"以下路径已过度测试，跳过: {over_tested[:3]}"] if over_tested else []),
                should_switch_strategy=bool(over_tested),
            )
        logger.warning("反思[规则兜底-%s]: %s", r.level.value, r.root_cause)
        return r

    def _llm_analyze(self, recent: list[ActionRecord]) -> Reflection | None:
        """用顾问模型做深度归因"""
        import json as _json

        history_text = "\n".join(
            f"- [{i+1}] 工具={a.vuln_type} 端点={a.endpoint[:60]} "
            f"状态={a.response_code} payload={a.payload[:80]}"
            + (f" 错误={a.error_msg[:50]}" if a.error_msg else "")
            + (f" 响应摘要={a.response_body[:100]}" if a.response_body else "")
            for i, a in enumerate(recent)
        )
        strategies_text = "\n".join(
            f"- {k}: {v}次" for k, v in
            sorted(self._tried_strategies.items(), key=lambda x: -x[1])[:10]
        )

        prompt = _LLM_ANALYZE_PROMPT.format(
            n=len(recent),
            history=history_text,
            strategies=strategies_text,
        )

        try:
            raw = self._llm.chat(
                [{"role": "user", "content": prompt}],
                role="advisor",
            )
            if not raw:
                return None

            # 提取 JSON
            import re
            m = re.search(r'\{[\s\S]+\}', raw)
            if not m:
                return None
            data = _json.loads(m.group(0))

            level_map = {
                "L1-工具错误": FailureLevel.L1,
                "L2-信息不足": FailureLevel.L2,
                "L3-策略错误": FailureLevel.L3,
                "L4-认知偏差": FailureLevel.L4,
            }
            level_str = data.get("level", "L2-信息不足")
            level = level_map.get(level_str, FailureLevel.L2)

            return Reflection(
                level=level,
                root_cause=data.get("root_cause", "LLM归因"),
                missed_clues=data.get("missed_clues", []),
                suggestions=data.get("suggestions", []),
                should_switch_strategy=data.get("should_switch_strategy", False),
            )
        except Exception as e:
            logger.debug("LLM归因失败，回退规则: %s", e)
            return None

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
