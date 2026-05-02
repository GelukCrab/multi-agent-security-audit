"""
经验自蒸馏
=========
攻击成功后，让LLM提炼经验并写入向量知识库，形成自我进化的正向循环。
"""

from __future__ import annotations

import json
import logging

logger = logging.getLogger(__name__)

DISTILL_PROMPT = """你是一名渗透测试经验总结专家。根据以下攻击成功记录，提炼出结构化的经验知识。

## 攻击记录
{finding_json}

## 输出格式(JSON)
```json
{{
  "vuln_type": "漏洞类型(如: SQL注入-报错注入/SQL注入-时间盲注/RCE-命令注入/SSTI-Jinja2等)",
  "target_info": "目标特征描述(如: PHP+MySQL登录表单/Node.js模板渲染/Java Spring Boot等)",
  "payload": "最终有效的payload(精简版)",
  "bypass_method": "绕过手法(如: 宽字节绕过addslashes/双写绕过OR过滤/括号代替空格等，没有则留空)",
  "description": "一句话经验总结(下次遇到类似目标时的快速指引)",
  "tags": ["标签1", "标签2", "标签3"]
}}
```

只输出JSON，不要其他内容。"""


def distill_experience(llm_provider, finding: dict) -> dict | None:
    """从攻击成功记录中提炼经验"""
    if not llm_provider:
        return None

    finding_json = json.dumps(finding, ensure_ascii=False, indent=2)
    prompt = DISTILL_PROMPT.format(finding_json=finding_json)

    try:
        response = llm_provider.chat(
            [{"role": "user", "content": prompt}],
            role="advisor",
        )
        if not response:
            return None

        response = response.strip()
        if response.startswith("```"):
            lines = response.split("\n")
            response = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        import re
        match = re.search(r'\{[\s\S]*\}', response)
        if match:
            return json.loads(match.group())
        return json.loads(response)
    except Exception as e:
        logger.error("经验蒸馏失败: %s", e)
        return None


def auto_distill_and_store(llm_provider, knowledge_base, findings: list[dict]) -> int:
    """自动蒸馏所有攻击成功记录并存入知识库"""
    if not knowledge_base or not knowledge_base.available:
        return 0
    if not findings:
        return 0

    stored = 0
    for finding in findings:
        logger.info("蒸馏经验: %s @ %s", finding.get("vuln_type"), finding.get("endpoint"))
        experience = distill_experience(llm_provider, finding)
        if experience:
            doc_id = knowledge_base.store_experience(
                vuln_type=experience.get("vuln_type", ""),
                target_info=experience.get("target_info", ""),
                payload=experience.get("payload", ""),
                bypass_method=experience.get("bypass_method", ""),
                description=experience.get("description", ""),
                tags=experience.get("tags", []),
            )
            if doc_id:
                stored += 1

    logger.info("经验蒸馏完成: %d/%d 条成功入库", stored, len(findings))
    return stored
