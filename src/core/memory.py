"""
记忆系统 — 运行记忆 + 经验持久化
================================
借鉴LingXi的三层记忆架构:
  1. 运行记忆(热路径) — 当前审计的实时状态
  2. 经验存储(持久化) — 历史审计的成功/失败经验
  3. 知识检索 — 外部知识库(预留接口)

按目标域名做经验持久化，相同目标再次审计时自动加载历史经验。
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

MEMORY_DIR = Path(__file__).resolve().parent.parent.parent / "memory"


@dataclass
class AuditMemory:
    """单次审计的运行记忆"""
    target: str
    start_time: str = ""
    frameworks: list[str] = field(default_factory=list)
    endpoints_found: int = 0
    vulns_found: int = 0
    successful_payloads: list[dict] = field(default_factory=list)
    failed_paths: list[str] = field(default_factory=list)
    verified_chains: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


@dataclass
class Experience:
    """持久化的审计经验"""
    target_domain: str
    last_audit: str
    total_audits: int = 0
    known_vulns: list[dict] = field(default_factory=list)
    known_safe: list[str] = field(default_factory=list)
    effective_payloads: list[dict] = field(default_factory=list)
    dead_ends: list[str] = field(default_factory=list)
    verified_chains: list[str] = field(default_factory=list)


class MemoryStore:
    """记忆存储：管理运行记忆和持久化经验"""

    def __init__(self, memory_dir: Path | None = None) -> None:
        self._dir = memory_dir or MEMORY_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._current: AuditMemory | None = None

    def start_audit(self, target: str) -> AuditMemory:
        self._current = AuditMemory(
            target=target,
            start_time=datetime.now().isoformat(),
        )
        logger.info("创建审计记忆: %s", target)
        return self._current

    @property
    def current(self) -> AuditMemory | None:
        return self._current

    def record_success(self, endpoint: str, vuln_type: str, payload: str) -> None:
        if not self._current:
            return
        self._current.successful_payloads.append({
            "endpoint": endpoint, "vuln_type": vuln_type,
            "payload": payload, "time": datetime.now().isoformat(),
        })
        self._current.vulns_found += 1

    def record_failure(self, path: str) -> None:
        if not self._current:
            return
        if path not in self._current.failed_paths:
            self._current.failed_paths.append(path)

    def record_chain(self, chain: str) -> None:
        if not self._current:
            return
        self._current.verified_chains.append(chain)

    def save_experience(self) -> None:
        if not self._current:
            return
        domain = self._extract_domain(self._current.target)
        exp_path = self._dir / f"{domain}.json"
        exp = self._load_experience(domain)
        exp.last_audit = datetime.now().isoformat()
        exp.total_audits += 1
        for sp in self._current.successful_payloads:
            if sp not in exp.effective_payloads:
                exp.effective_payloads.append(sp)
        for vuln in self._current.successful_payloads:
            entry = {"endpoint": vuln["endpoint"], "vuln_type": vuln["vuln_type"]}
            if entry not in exp.known_vulns:
                exp.known_vulns.append(entry)
        for dead in self._current.failed_paths:
            if dead not in exp.dead_ends:
                exp.dead_ends.append(dead)
        for chain in self._current.verified_chains:
            if chain not in exp.verified_chains:
                exp.verified_chains.append(chain)
        with open(exp_path, "w", encoding="utf-8") as f:
            json.dump(asdict(exp), f, ensure_ascii=False, indent=2)
        logger.info("经验已保存: %s (累计%d次审计)", exp_path, exp.total_audits)

    def load_experience(self, target: str) -> Experience | None:
        domain = self._extract_domain(target)
        exp = self._load_experience(domain)
        if exp.total_audits > 0:
            logger.info("加载历史经验: %s (%d次审计, %d个已知漏洞)",
                        domain, exp.total_audits, len(exp.known_vulns))
            return exp
        return None

    def _load_experience(self, domain: str) -> Experience:
        exp_path = self._dir / f"{domain}.json"
        if exp_path.exists():
            try:
                with open(exp_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                return Experience(**data)
            except Exception:
                pass
        return Experience(target_domain=domain, last_audit="")

    @staticmethod
    def _extract_domain(url: str) -> str:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        domain = parsed.hostname or url
        return domain.replace(".", "_")
