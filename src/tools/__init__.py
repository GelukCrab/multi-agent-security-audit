"""工具注册与分发"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable

logger = logging.getLogger(__name__)


class ToolRegistry:
    """工具注册中心：注册工具函数，生成OpenAI schema，分发调用"""

    def __init__(self) -> None:
        self._tools: dict[str, dict] = {}
        self._handlers: dict[str, Callable] = {}

    def register(self, name: str, description: str,
                 parameters: dict, handler: Callable) -> None:
        self._tools[name] = {
            "type": "function",
            "function": {
                "name": name,
                "description": description,
                "parameters": parameters,
            },
        }
        self._handlers[name] = handler
        logger.debug("注册工具: %s", name)

    def get_schemas(self) -> list[dict]:
        return list(self._tools.values())

    async def execute(self, name: str, arguments: str) -> str:
        handler = self._handlers.get(name)
        if not handler:
            return json.dumps({"error": f"未知工具: {name}"})
        try:
            args = json.loads(arguments) if arguments else {}
        except json.JSONDecodeError:
            return json.dumps({"error": f"参数JSON解析失败: {arguments[:200]}"})
        try:
            import asyncio
            if asyncio.iscoroutinefunction(handler):
                result = await handler(**args)
            else:
                result = handler(**args)
            return json.dumps(result, ensure_ascii=False, default=str)
        except Exception as e:
            logger.error("工具 %s 执行失败: %s", name, e)
            return json.dumps({"error": str(e)})
