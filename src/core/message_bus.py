"""Agent间消息总线 — 协调多Agent通信"""

from __future__ import annotations

import asyncio
import logging
from collections import defaultdict
from typing import Callable, Awaitable

from src.core import AgentMessage

logger = logging.getLogger(__name__)


class MessageBus:
    """基于发布-订阅模式的Agent间通信总线"""

    def __init__(self) -> None:
        self._subscribers: dict[str, list[Callable[[AgentMessage], Awaitable[None]]]] = defaultdict(list)
        self._history: list[AgentMessage] = []

    def subscribe(self, msg_type: str, handler: Callable[[AgentMessage], Awaitable[None]]) -> None:
        self._subscribers[msg_type].append(handler)
        logger.debug("订阅消息类型: %s", msg_type)

    async def publish(self, message: AgentMessage) -> None:
        self._history.append(message)
        logger.info("[%s -> %s] 类型=%s", message.sender, message.receiver, message.msg_type)
        for handler in self._subscribers.get(message.msg_type, []):
            await handler(message)

    @property
    def history(self) -> list[AgentMessage]:
        return list(self._history)
