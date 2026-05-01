"""页面分析工具"""

from __future__ import annotations

import re
import logging
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


def extract_forms(html: str) -> list[dict]:
    """从HTML中提取所有表单及其输入字段"""
    forms = []
    form_pattern = re.compile(
        r'<form\b([^>]*)>(.*?)</form>', re.IGNORECASE | re.DOTALL
    )
    for form_match in form_pattern.finditer(html):
        attrs_str = form_match.group(1)
        form_body = form_match.group(2)

        action = ""
        m = re.search(r'action=["\']([^"\']*)["\']', attrs_str, re.IGNORECASE)
        if m:
            action = m.group(1)

        method = "GET"
        m = re.search(r'method=["\']([^"\']*)["\']', attrs_str, re.IGNORECASE)
        if m:
            method = m.group(1).upper()

        inputs = []
        input_pattern = re.compile(
            r'<(?:input|select|textarea)\b([^>]*)/?>', re.IGNORECASE
        )
        for inp_match in input_pattern.finditer(form_body):
            inp_attrs = inp_match.group(1)
            name = ""
            m = re.search(r'name=["\']([^"\']*)["\']', inp_attrs, re.IGNORECASE)
            if m:
                name = m.group(1)
            inp_type = "text"
            m = re.search(r'type=["\']([^"\']*)["\']', inp_attrs, re.IGNORECASE)
            if m:
                inp_type = m.group(1)
            value = ""
            m = re.search(r'value=["\']([^"\']*)["\']', inp_attrs, re.IGNORECASE)
            if m:
                value = m.group(1)
            if name:
                inputs.append({"name": name, "type": inp_type, "value": value})

        forms.append({"action": action, "method": method, "inputs": inputs})

    return forms


def extract_links(html: str, base_url: str) -> list[dict]:
    """从HTML中提取所有链接"""
    links = []
    seen = set()
    for m in re.finditer(r'<a\b[^>]*href=["\']([^"\'#]*)["\'][^>]*>(.*?)</a>',
                         html, re.IGNORECASE | re.DOTALL):
        href = m.group(1).strip()
        text = re.sub(r'<[^>]+>', '', m.group(2)).strip()
        if not href or href.startswith(("javascript:", "mailto:")):
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
            "matches": matches[:10],
        }
    except re.error as e:
        return {"error": f"正则表达式错误: {e}"}


def diff_responses(response_a: str, response_b: str) -> dict:
    """比较两个响应的差异"""
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
