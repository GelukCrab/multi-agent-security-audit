"""
LLM Provider — 统一的大模型调用层
=================================
支持OpenAI兼容协议(DeepSeek/GPT/通义等都走这个)。
角色分离: 主攻手(main) + 顾问(advisor)
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
    """统一LLM调用层，支持主攻手和顾问两个角色"""

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

    def chat(self, messages: list[dict], role: str = "main",
             temperature: float | None = None,
             max_tokens: int | None = None) -> str:
        """发送对话请求，role='main'用主攻手，role='advisor'用顾问"""
        if role == "advisor" and self._advisor_client and self._advisor_config:
            client = self._advisor_client
            config = self._advisor_config
        else:
            client = self._main_client
            config = self._main_config

        try:
            response = client.chat.completions.create(
                model=config.model,
                messages=messages,
                temperature=temperature or config.temperature,
                max_tokens=max_tokens or config.max_tokens,
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            logger.error("[%s] LLM调用失败: %s", role, e)
            return ""

    def chat_json(self, messages: list[dict], role: str = "main") -> list | dict | None:
        """发送对话请求并解析JSON响应"""
        text = self.chat(messages, role=role, temperature=0.3)
        if not text:
            return None
        text = text.strip()
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            import re
            match = re.search(r'[\[\{].*[\]\}]', text, re.DOTALL)
            if match:
                try:
                    return json.loads(match.group())
                except json.JSONDecodeError:
                    pass
            logger.warning("JSON解析失败，原始响应: %s...", text[:200])
            return None

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
        model=llm_cfg.get("main_model", "") or os.environ.get("LLM_MAIN_MODEL", "deepseek-reasoner"),
        max_tokens=llm_cfg.get("max_tokens", 4096),
        temperature=llm_cfg.get("temperature", 0.7),
    )

    advisor_cfg = llm_cfg.get("advisor", {})
    advisor_config = None
    if advisor_cfg.get("enabled", True):
        advisor_config = LLMConfig(
            base_url=advisor_cfg.get("base_url", "") or base_url,
            api_key=advisor_cfg.get("api_key", "") or api_key,
            model=advisor_cfg.get("model", "") or os.environ.get("LLM_ADVISOR_MODEL", "deepseek-chat"),
            max_tokens=advisor_cfg.get("max_tokens", 2048),
            temperature=advisor_cfg.get("temperature", 0.5),
        )

    try:
        return LLMProvider(main_config, advisor_config)
    except ImportError as e:
        logger.warning("LLM Provider创建失败: %s", e)
        return None
