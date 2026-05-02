"""
技能(Skill)注册与管理系统
========================
基于Markdown文档的可插拔技能定义，支持:
- 从skills目录自动发现和加载技能
- 基于frontmatter元数据做场景匹配
- 运行时按目标特征自动选择技能组合
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Awaitable

logger = logging.getLogger(__name__)

SKILLS_DIR = Path(__file__).resolve().parent.parent.parent / "skills"


@dataclass
class SkillMeta:
    """技能元数据，从SKILL.md的frontmatter解析"""
    name: str
    description: str
    tags: list[str] = field(default_factory=list)
    priority: int = 50
    phase: str = ""       # recon / exploit / post-exploit
    chain: str = ""       # 技能链: recon -> exploit -> post-exploit
    author: str = ""


@dataclass
class Skill:
    """一个完整的技能定义"""
    meta: SkillMeta
    body: str
    source: Path
    payloads: dict[str, list[str]] = field(default_factory=dict)
    detect_patterns: list[str] = field(default_factory=list)
    resources: list[Path] = field(default_factory=list)


def _parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """解析Markdown frontmatter，返回(元数据dict, 正文)"""
    if not text.startswith("---\n"):
        return {}, text
    parts = text.split("\n---\n", 1)
    if len(parts) != 2:
        return {}, text
    meta = {}
    for line in parts[0].split("\n")[1:]:
        if ":" in line:
            key, val = line.split(":", 1)
            meta[key.strip()] = val.strip().strip('"').strip("'")
    return meta, parts[1].strip()


def _parse_skill_md(path: Path) -> Skill | None:
    """从SKILL.md文件解析出Skill对象"""
    try:
        raw = path.read_text(encoding="utf-8")
    except Exception as e:
        logger.warning("读取技能文件失败 %s: %s", path, e)
        return None

    meta_dict, body = _parse_frontmatter(raw)

    tags_raw = meta_dict.get("tags", "")
    tags = [t.strip() for t in tags_raw.split(",") if t.strip()]

    meta = SkillMeta(
        name=meta_dict.get("name", path.parent.name),
        description=meta_dict.get("description", ""),
        tags=tags,
        priority=int(meta_dict.get("priority", "50")),
        phase=meta_dict.get("phase", ""),
        chain=meta_dict.get("chain", ""),
        author=meta_dict.get("author", ""),
    )

    payloads = _extract_code_blocks(body, "payloads")
    detect_patterns = _extract_list_section(body, "detect")

    resources = []
    res_dir = path.parent / "resources"
    if res_dir.is_dir():
        resources = sorted(res_dir.rglob("*.md"))

    return Skill(
        meta=meta, body=body, source=path,
        payloads=payloads, detect_patterns=detect_patterns,
        resources=resources,
    )


def _extract_code_blocks(text: str, section_keyword: str) -> dict[str, list[str]]:
    """提取指定section下的代码块内容"""
    result: dict[str, list[str]] = {}
    in_section = False
    current_label = ""
    in_code = False
    code_lines: list[str] = []

    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("## ") and section_keyword.lower() in stripped.lower():
            in_section = True
            continue
        if in_section and stripped.startswith("## "):
            break
        if not in_section:
            continue
        if stripped.startswith("### "):
            current_label = stripped[4:].strip()
            continue
        if stripped.startswith("```"):
            if in_code:
                if current_label and code_lines:
                    result[current_label] = [l for l in code_lines if l.strip()]
                code_lines = []
                in_code = False
            else:
                in_code = True
            continue
        if in_code:
            code_lines.append(line)

    return result


def _extract_list_section(text: str, section_keyword: str) -> list[str]:
    """提取指定section下的列表项"""
    items: list[str] = []
    in_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("## ") and section_keyword.lower() in stripped.lower():
            in_section = True
            continue
        if in_section and stripped.startswith("## "):
            break
        if in_section and stripped.startswith("- "):
            items.append(stripped[2:].strip())
    return items


class SkillRegistry:
    """技能注册中心：自动发现、加载、匹配技能"""

    def __init__(self, skills_dir: Path | None = None) -> None:
        self._skills_dir = skills_dir or SKILLS_DIR
        self._skills: dict[str, Skill] = {}
        self._loaded = False

    def load(self) -> None:
        """扫描skills目录，加载所有技能"""
        self._skills.clear()
        if not self._skills_dir.exists():
            logger.info("技能目录不存在: %s，使用内置技能", self._skills_dir)
            self._load_builtin_skills()
            self._loaded = True
            return

        for skill_md in sorted(self._skills_dir.rglob("SKILL.md")):
            skill = _parse_skill_md(skill_md)
            if skill:
                self._skills[skill.meta.name] = skill
                logger.debug("加载技能: %s (%s)", skill.meta.name, skill.meta.description)

        logger.info("从目录加载 %d 个技能", len(self._skills))
        self._loaded = True

    def _load_builtin_skills(self) -> None:
        """加载内置技能（无外部skills目录时的回退）"""
        from src.utils import payload_db
        builtins = [
            Skill(
                meta=SkillMeta(name="sqli", description="SQL注入检测", tags=["sql", "injection", "database"], priority=90),
                body="SQL注入检测技能：报错注入、联合注入、时间盲注、布尔盲注",
                source=Path("builtin://sqli"),
                payloads={"sqli": payload_db.SQLI_PAYLOADS},
                detect_patterns=[r"SQL syntax", r"mysql_fetch", r"ORA-\d+", r"SQLSTATE"],
            ),
            Skill(
                meta=SkillMeta(name="xss", description="XSS跨站脚本检测", tags=["xss", "script", "reflect"], priority=70),
                body="XSS检测技能：反射型、存储型、DOM型",
                source=Path("builtin://xss"),
                payloads={"xss": payload_db.XSS_PAYLOADS},
                detect_patterns=[r"<script>", r"onerror=", r"javascript:"],
            ),
            Skill(
                meta=SkillMeta(name="ssti", description="服务端模板注入检测", tags=["ssti", "template", "jinja", "freemarker"], priority=85),
                body="SSTI检测技能：Jinja2、Freemarker、Velocity、Thymeleaf",
                source=Path("builtin://ssti"),
                payloads={"ssti": payload_db.SSTI_PAYLOADS},
                detect_patterns=[r"49"],
            ),
            Skill(
                meta=SkillMeta(name="idor", description="越权访问检测", tags=["idor", "authz", "id"], priority=80),
                body="IDOR检测技能：水平越权、垂直越权、资源ID遍历",
                source=Path("builtin://idor"),
                payloads={},
                detect_patterns=[],
            ),
            Skill(
                meta=SkillMeta(name="unauth", description="未授权访问检测", tags=["unauth", "bypass", "auth"], priority=95),
                body="未授权访问检测：删除认证头、路径绕过、Header伪造",
                source=Path("builtin://unauth"),
                payloads={"bypass_headers": [str(h) for h in payload_db.AUTH_BYPASS_HEADERS]},
                detect_patterns=[],
            ),
            Skill(
                meta=SkillMeta(name="rce", description="远程命令执行检测", tags=["rce", "cmd", "command", "exec"], priority=95),
                body="RCE检测技能：命令注入、反序列化、表达式注入",
                source=Path("builtin://rce"),
                payloads={"cmd_injection": payload_db.CMD_INJECTION_PAYLOADS},
                detect_patterns=[r"uid=\d+", r"root:", r"www-data"],
            ),
        ]
        for skill in builtins:
            self._skills[skill.meta.name] = skill
        logger.info("加载 %d 个内置技能", len(builtins))

    def get(self, name: str) -> Skill | None:
        return self._skills.get(name)

    def all(self) -> list[Skill]:
        return sorted(self._skills.values(), key=lambda s: s.meta.priority, reverse=True)

    def get_by_phase(self, phase: str) -> list[Skill]:
        """按阶段获取技能: recon / exploit / post-exploit"""
        return sorted(
            [s for s in self._skills.values() if s.meta.phase == phase],
            key=lambda s: s.meta.priority, reverse=True,
        )

    def get_chain(self, start_skill: str) -> list[Skill]:
        """获取技能链：根据chain字段解析依赖顺序"""
        skill = self._skills.get(start_skill)
        if not skill or not skill.meta.chain:
            return [skill] if skill else []
        chain_names = [n.strip() for n in skill.meta.chain.split("->")]
        return [self._skills[n] for n in chain_names if n in self._skills]

    def match_by_tags(self, keywords: list[str]) -> list[Skill]:
        """根据关键词匹配相关技能"""
        matched = []
        kw_lower = [k.lower() for k in keywords]
        for skill in self._skills.values():
            tags_lower = [t.lower() for t in skill.meta.tags]
            if any(kw in tags_lower or any(kw in tag for tag in tags_lower) for kw in kw_lower):
                matched.append(skill)
        matched.sort(key=lambda s: s.meta.priority, reverse=True)
        return matched

    def match_by_context(self, endpoint_path: str, frameworks: list[str]) -> list[Skill]:
        """根据端点路径和框架指纹自动选择技能"""
        keywords = []
        path_lower = endpoint_path.lower()
        if any(kw in path_lower for kw in ("login", "user", "auth", "session")):
            keywords.extend(["sql", "auth", "bypass"])
        if any(kw in path_lower for kw in ("search", "query", "filter", "sort")):
            keywords.extend(["sql", "xss"])
        if any(kw in path_lower for kw in ("upload", "file", "import", "attach")):
            keywords.extend(["upload", "rce"])
        if any(kw in path_lower for kw in ("exec", "run", "cmd", "ping")):
            keywords.extend(["rce", "cmd"])
        if any(kw in path_lower for kw in ("template", "render", "view")):
            keywords.extend(["ssti", "template"])
        if any(kw in path_lower for kw in ("url", "webhook", "callback", "proxy")):
            keywords.extend(["ssrf"])
        for fw in frameworks:
            fw_lower = fw.lower()
            if "spring" in fw_lower:
                keywords.extend(["ssti", "rce"])
            if "flask" in fw_lower or "django" in fw_lower:
                keywords.extend(["ssti"])
            if "php" in fw_lower or "laravel" in fw_lower:
                keywords.extend(["sql", "rce", "upload"])
        if not keywords:
            keywords = ["sql", "xss", "unauth"]
        return self.match_by_tags(keywords)
