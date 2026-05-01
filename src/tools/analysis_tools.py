"""页面分析工具"""

from __future__ import annotations

import re
import logging
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


def _get_attr(attrs_str: str, name: str, default: str = "") -> str:
    """从HTML属性字符串中提取属性值，支持有引号和无引号"""
    m = re.search(
        rf'{name}\s*=\s*(?:["\']([^"\']*)["\']|([^\s>]+))',
        attrs_str, re.IGNORECASE,
    )
    if m:
        return m.group(1) if m.group(1) is not None else (m.group(2) or default)
    return default


def extract_forms(html: str, base_url: str = "") -> list[dict]:
    """从HTML中提取所有表单及其输入字段"""
    forms = []
    form_pattern = re.compile(
        r'<form\b([^>]*)>(.*?)</form>', re.IGNORECASE | re.DOTALL
    )
    for form_match in form_pattern.finditer(html):
        attrs_str = form_match.group(1)
        form_body = form_match.group(2)

        action = _get_attr(attrs_str, "action")
        method = _get_attr(attrs_str, "method", "GET").upper()

        if not action and base_url:
            action = base_url
        elif action and base_url:
            action = urljoin(base_url, action)

        inputs = []
        input_pattern = re.compile(
            r'<(?:input|select|textarea)\b([^>]*)/?>', re.IGNORECASE
        )
        for inp_match in input_pattern.finditer(form_body):
            inp_attrs = inp_match.group(1)
            name = _get_attr(inp_attrs, "name")
            inp_type = _get_attr(inp_attrs, "type", "text")
            value = _get_attr(inp_attrs, "value")
            if name:
                inputs.append({"name": name, "type": inp_type, "value": value})

        forms.append({"action": action, "method": method, "inputs": inputs})

    return forms


def extract_links(html: str, base_url: str) -> list[dict]:
    """从HTML中提取所有链接"""
    links = []
    seen = set()
    href_pattern = re.compile(
        r'<a\b[^>]*href\s*=\s*(?:["\']([^"\'#]*)["\']|([^\s>#]+))[^>]*>(.*?)</a>',
        re.IGNORECASE | re.DOTALL,
    )
    for m in href_pattern.finditer(html):
        href = (m.group(1) if m.group(1) is not None else m.group(2) or "").strip()
        text = re.sub(r'<[^>]+>', '', m.group(3)).strip()
        if not href or href.startswith(("javascript:", "mailto:", "#")):
            continue
        full_url = urljoin(base_url, href)
        if full_url not in seen:
            seen.add(full_url)
            links.append({"href": full_url, "text": text[:100]})
    return links


def search_in_response(text: str, pattern: str) -> dict:
    """在响应文本中搜索正则模式"""
    try:
        matches = re.findall(pattern, text, re.IGNORECASE)
        return {
            "found": len(matches) > 0,
            "match_count": len(matches),
            "matches": [str(m)[:200] for m in matches[:10]],
        }
    except re.error as e:
        return {"error": f"正则表达式错误: {e}"}


def diff_responses(response_a: str, response_b: str) -> dict:
    """比较两个响应体的差异"""
    len_a = len(response_a)
    len_b = len(response_b)
    identical = response_a == response_b

    first_diff = -1
    if not identical:
        for i in range(min(len_a, len_b)):
            if response_a[i] != response_b[i]:
                first_diff = i
                break
        if first_diff == -1:
            first_diff = min(len_a, len_b)

    return {
        "identical": identical,
        "length_a": len_a,
        "length_b": len_b,
        "length_diff": abs(len_a - len_b),
        "first_diff_at": first_diff,
    }
