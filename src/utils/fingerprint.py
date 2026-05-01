"""框架指纹识别"""

from __future__ import annotations

import re
import logging

import httpx

logger = logging.getLogger(__name__)

FINGERPRINTS: dict[str, list[dict]] = {
    "Spring Boot": [
        {"header": "X-Application-Context", "pattern": r".+"},
        {"path": "/actuator", "status": [200]},
        {"body_pattern": r"Whitelabel Error Page"},
    ],
    "Django": [
        {"header": "X-Frame-Options", "pattern": r"DENY|SAMEORIGIN"},
        {"body_pattern": r"csrfmiddlewaretoken"},
        {"body_pattern": r"__debug__"},
    ],
    "Flask": [
        {"header": "Server", "pattern": r"Werkzeug"},
        {"body_pattern": r"Traceback \(most recent call last\)"},
    ],
    "Laravel": [
        {"header": "Set-Cookie", "pattern": r"laravel_session"},
        {"path": "/.env", "body_pattern": r"APP_KEY="},
    ],
    "Express": [
        {"header": "X-Powered-By", "pattern": r"Express"},
    ],
    "Nginx": [
        {"header": "Server", "pattern": r"nginx"},
    ],
    "Apache Tomcat": [
        {"header": "Server", "pattern": r"Apache-Coyote|Tomcat"},
        {"body_pattern": r"Apache Tomcat"},
    ],
    "ThinkPHP": [
        {"header": "Set-Cookie", "pattern": r"think_"},
        {"body_pattern": r"thinkphp|ThinkPHP"},
    ],
}

COMMON_LEAK_PATHS = [
    "/.git/HEAD",
    "/.svn/entries",
    "/.env",
    "/.DS_Store",
    "/swagger-ui.html",
    "/swagger-ui/",
    "/v2/api-docs",
    "/v3/api-docs",
    "/actuator",
    "/actuator/env",
    "/actuator/heapdump",
    "/druid/index.html",
    "/nacos/",
    "/WEB-INF/web.xml",
    "/robots.txt",
    "/sitemap.xml",
    "/crossdomain.xml",
    "/phpinfo.php",
    "/server-status",
    "/server-info",
]


async def identify_framework(
    client: httpx.AsyncClient, base_url: str
) -> list[str]:
    """对目标进行指纹识别，返回匹配的框架列表"""
    detected: list[str] = []
    try:
        resp = await client.get(base_url)
    except Exception as e:
        logger.warning("指纹识别请求失败: %s", e)
        return detected

    for framework, rules in FINGERPRINTS.items():
        for rule in rules:
            if "header" in rule:
                val = resp.headers.get(rule["header"], "")
                if re.search(rule["pattern"], val, re.IGNORECASE):
                    detected.append(framework)
                    break
            if "body_pattern" in rule and "path" not in rule:
                if re.search(rule["body_pattern"], resp.text, re.IGNORECASE):
                    detected.append(framework)
                    break

    logger.info("识别到框架: %s", detected or "未识别")
    return detected
