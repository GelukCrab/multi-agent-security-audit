"""
RAG向量知识库
============
基于ChromaDB的向量知识库，支持:
- CVE/漏洞知识检索
- 攻击经验存储与检索
- 经验自蒸馏(攻击成功后自动提炼写入)
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

DB_DIR = Path(__file__).resolve().parent.parent.parent / "knowledge_db"

try:
    import chromadb
    HAS_CHROMADB = True
except ImportError:
    HAS_CHROMADB = False


class KnowledgeBase:
    """向量知识库：存储和检索渗透经验与CVE知识"""

    def __init__(self, db_dir: Path | None = None) -> None:
        self._dir = db_dir or DB_DIR
        self._dir.mkdir(parents=True, exist_ok=True)
        self._client = None
        self._exp_collection = None
        self._cve_collection = None

        if not HAS_CHROMADB:
            logger.warning("chromadb未安装，知识库不可用")
            return

        try:
            self._client = chromadb.PersistentClient(
                path=str(self._dir),
            )
            self._exp_collection = self._client.get_or_create_collection(
                name="attack_experience",
                metadata={"description": "渗透攻击经验库"},
            )
            self._cve_collection = self._client.get_or_create_collection(
                name="cve_knowledge",
                metadata={"description": "CVE漏洞知识库"},
            )
            logger.info("知识库初始化完成: %s (经验%d条, CVE%d条)",
                        self._dir,
                        self._exp_collection.count(),
                        self._cve_collection.count())
        except Exception as e:
            logger.error("知识库初始化失败: %s", e)

    @property
    def available(self) -> bool:
        return self._client is not None

    # ==================== 经验存储与检索 ====================

    def store_experience(
        self,
        vuln_type: str,
        target_info: str,
        payload: str,
        bypass_method: str = "",
        description: str = "",
        tags: list[str] | None = None,
    ) -> str:
        """存储一条攻击经验"""
        if not self.available:
            return ""

        doc_id = f"exp_{datetime.now().strftime('%Y%m%d%H%M%S')}_{self._exp_collection.count()}"
        document = f"漏洞类型: {vuln_type}\n目标特征: {target_info}\n有效payload: {payload}"
        if bypass_method:
            document += f"\n绕过手法: {bypass_method}"
        if description:
            document += f"\n经验总结: {description}"

        metadata = {
            "vuln_type": vuln_type,
            "timestamp": datetime.now().isoformat(),
            "tags": ",".join(tags or []),
        }

        try:
            self._exp_collection.add(
                ids=[doc_id],
                documents=[document],
                metadatas=[metadata],
            )
            logger.info("经验入库: %s [%s]", doc_id, vuln_type)
            return doc_id
        except Exception as e:
            logger.error("经验入库失败: %s", e)
            return ""

    def search_experience(self, query: str, n_results: int = 3) -> list[dict]:
        """检索相关攻击经验"""
        if not self.available or self._exp_collection.count() == 0:
            return []

        try:
            results = self._exp_collection.query(
                query_texts=[query],
                n_results=min(n_results, self._exp_collection.count()),
            )
            experiences = []
            for i, doc in enumerate(results["documents"][0]):
                exp = {
                    "content": doc,
                    "metadata": results["metadatas"][0][i],
                    "distance": results["distances"][0][i] if results.get("distances") else None,
                }
                experiences.append(exp)
            return experiences
        except Exception as e:
            logger.error("经验检索失败: %s", e)
            return []

    # ==================== CVE知识存储与检索 ====================

    def store_cve(
        self,
        cve_id: str,
        description: str,
        affected_product: str = "",
        exploit_info: str = "",
        severity: str = "",
    ) -> str:
        """存储CVE知识"""
        if not self.available:
            return ""

        document = f"CVE编号: {cve_id}\n描述: {description}"
        if affected_product:
            document += f"\n影响产品: {affected_product}"
        if exploit_info:
            document += f"\n利用方式: {exploit_info}"

        metadata = {
            "cve_id": cve_id,
            "severity": severity,
            "affected_product": affected_product,
            "timestamp": datetime.now().isoformat(),
        }

        try:
            self._cve_collection.add(
                ids=[cve_id],
                documents=[document],
                metadatas=[metadata],
            )
            logger.info("CVE入库: %s", cve_id)
            return cve_id
        except Exception as e:
            logger.error("CVE入库失败: %s", e)
            return ""

    def search_cve(self, query: str, n_results: int = 3) -> list[dict]:
        """检索相关CVE知识"""
        if not self.available or self._cve_collection.count() == 0:
            return []

        try:
            results = self._cve_collection.query(
                query_texts=[query],
                n_results=min(n_results, self._cve_collection.count()),
            )
            cves = []
            for i, doc in enumerate(results["documents"][0]):
                cves.append({
                    "content": doc,
                    "metadata": results["metadatas"][0][i],
                })
            return cves
        except Exception as e:
            logger.error("CVE检索失败: %s", e)
            return []

    # ==================== 统计 ====================

    @property
    def stats(self) -> dict:
        if not self.available:
            return {"available": False}
        return {
            "available": True,
            "experiences": self._exp_collection.count(),
            "cves": self._cve_collection.count(),
        }
