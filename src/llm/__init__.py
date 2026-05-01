"""
LLM Provider — 统一的大模型调用层
=================================
支持OpenAI兼容协议(DeepSeek/GPT/通义等都走这个)。
角色分离: 主攻手(main) + 顾问(advisor)
两阶段调用: 思考模式(深度推理) + 执行模式(Function Calling)
"""

from __future__ import annotations

import os
import json
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

try:
    from openai import OpenAI
    HAS_OPENAI = True
except ImportError:
    HAS_OPENAI = False


@dataclass
class LLMConfig:
    """单个LLM角色的配置"""
    base_url: str
    api_key: str
    model: str
    max_tokens: int = 4096
    temperature: float = 0.7


class LLMProvider:
    """统一LLM调用层，支持思考模式和执行模式"""

    def __init__(self, main_config: LLMConfig, advisor_config: LLMConfig | None = None) -> None:
        if not HAS_OPENAI:
            raise ImportError("需要安装openai库: pip install openai")

        self._main_client = OpenAI(
            base_url=main_config.base_url,
            api_key=main_config.api_key,
        )
        self._main_config = main_config

        self._advisor_client = None
        self._advisor_config = advisor_config
        if advisor_config:
            self._advisor_client = OpenAI(
                base_url=advisor_config.base_url,
                api_key=advisor_config.api_key,
            )

        logger.info("主攻手模型: %s (%s)", main_config.model, main_config.base_url)
        if advisor_config:
            logger.info("顾问模型: %s (%s)", advisor_config.model, advisor_config.base_url)

    def _get_client_config(self, role: str) -> tuple:
        if role == "advisor" and self._advisor_client and self._advisor_config:
            return self._advisor_client, self._advisor_config
        return self._main_client, self._main_config

    def think(self, messages: list[dict], role: str = "main") -> tuple[str, str]:
        """思考模式：深度推理，返回(reasoning, content)"""
        client, config = self._get_client_config(role)
        logger.debug("[%s][思考] 调用 %s", role, config.model)

        try:
            response = client.chat.completions.create(
                model=config.model,
                messages=messages,
                max_tokens=config.max_tokens,
            )
            msg = response.choices[0].message
            usage = response.usage
            if usage:
                logger.debug("[%s][思考] tokens: prompt=%d completion=%d total=%d",
                            role, usage.prompt_tokens, usage.completion_tokens, usage.total_tokens)

            reasoning = getattr(msg, "reasoning_content", None) or ""
            content = msg.content or ""

            if reasoning:
                logger.debug("[%s][思考] 推理: %s...", role, reasoning[:300])
            logger.debug("[%s][思考] 结论: %s...", role, content[:300])
            return reasoning, content
        except Exception as e:
            logger.error("[%s][思考] 失败: %s", role, e)
            return "", ""

    def execute(self, messages: list[dict], tools: list[dict],
                role: str = "main") -> dict:
        """执行模式：关闭思考，启用Function Calling"""
        client, config = self._get_client_config(role)
        logger.debug("[%s][执行] 调用 %s | 工具数=%d", role, config.model, len(tools))

        try:
            extra_body = {"thinking": {"type": "disabled"}}
            response = client.chat.completions.create(
                model=config.model,
                messages=messages,
                tools=tools if tools else None,
                tool_choice="auto" if tools else None,
                max_tokens=config.max_tokens,
                extra_body=extra_body,
            )
            msg = response.choices[0].message
            usage = response.usage
            if usage:
                logger.debug("[%s][执行] tokens: prompt=%d completion=%d total=%d",
                            role, usage.prompt_tokens, usage.completion_tokens, usage.total_tokens)

            result = {"role": "assistant", "content": msg.content or ""}
            if msg.tool_calls:
                result["tool_calls"] = [
                    {
                        "id": tc.id,
                        "type": "function",
                        "function": {
                            "name": tc.function.name,
                            "arguments": tc.function.arguments,
                        },
                    }
                    for tc in msg.tool_calls
                ]
                logger.debug("[%s][执行] tool_calls: %s",
                            role, [tc.function.name for tc in msg.tool_calls])
            return result
        except Exception as e:
            logger.error("[%s][执行] 失败: %s", role, e)
            return {"role": "assistant", "content": f"执行失败: {e}"}

    def chat(self, messages: list[dict], role: str = "main",
             temperature: float | None = None,
             max_tokens: int | None = None) -> str:
        """普通对话（顾问用，关闭思考）"""
        client, config = self._get_client_config(role)
        try:
            extra_body = {"thinking": {"type": "disabled"}}
            response = client.chat.completions.create(
                model=config.model,
                messages=messages,
                temperature=temperature or config.temperature,
                max_tokens=max_tokens or config.max_tokens,
                extra_body=extra_body,
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            logger.error("[%s] chat失败: %s", role, e)
            return ""

    @property
    def has_advisor(self) -> bool:
        return self._advisor_client is not None


def create_provider_from_config(config: dict) -> LLMProvider | None:
    """从配置字典创建LLMProvider"""
    llm_cfg = config.get("llm", {})

    api_key = llm_cfg.get("api_key", "") or os.environ.get("DEEPSEEK_API_KEY", "") or os.environ.get("OPENAI_API_KEY", "")
    if not api_key:
        logger.warning("未配置API key，AI功能不可用")
        return None

    base_url = llm_cfg.get("base_url", "") or os.environ.get("LLM_BASE_URL", "https://api.deepseek.com")

    main_config = LLMConfig(
        base_url=base_url,
        api_key=api_key,
        model=llm_cfg.get("main_model", "") or os.environ.get("LLM_MAIN_MODEL", "deepseek-v4-pro"),
        max_tokens=llm_cfg.get("max_tokens", 4096),
        temperature=llm_cfg.get("temperature", 0.7),
    )

    advisor_cfg = llm_cfg.get("advisor", {})
    advisor_config = None
    if advisor_cfg.get("enabled", True):
        advisor_config = LLMConfig(
            base_url=advisor_cfg.get("base_url", "") or base_url,
            api_key=advisor_cfg.get("api_key", "") or api_key,
            model=advisor_cfg.get("model", "") or os.environ.get("LLM_ADVISOR_MODEL", "deepseek-v4-flash"),
            max_tokens=advisor_cfg.get("max_tokens", 2048),
            temperature=advisor_cfg.get("temperature", 0.5),
        )

    try:
        return LLMProvider(main_config, advisor_config)
    except ImportError as e:
        logger.warning("LLM Provider创建失败: %s", e)
        return None
