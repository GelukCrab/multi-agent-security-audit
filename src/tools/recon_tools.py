"""侦察工具集 — 端口扫描/目录爆破/子域枚举/JS分析"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

logger = logging.getLogger(__name__)

# 工具二进制路径
_BIN = Path(__file__).resolve().parent.parent.parent / "tools" / "bin"
NMAP_BIN      = str(_BIN / "nmap.exe")
FFUF_BIN      = str(_BIN / "ffuf.exe")
SUBFINDER_BIN = str(_BIN / "subfinder.exe")
HTTPX_BIN     = str(_BIN / "httpx.exe")

# 内置字典
_WORDLISTS = Path(__file__).resolve().parent.parent.parent / "tools" / "wordlists"

PROXY = "http://127.0.0.1:7890"


def _run(cmd: list[str], timeout: int = 120) -> tuple[str, str, int]:
    """运行外部命令，返回 (stdout, stderr, returncode)"""
    env = os.environ.copy()
    env["HTTP_PROXY"]  = PROXY
    env["HTTPS_PROXY"] = PROXY
    try:
        r = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, env=env,
        )
        return r.stdout, r.stderr, r.returncode
    except subprocess.TimeoutExpired:
        return "", "timeout", -1
    except FileNotFoundError as e:
        return "", f"binary not found: {e}", -1


# ── 端口扫描 ──────────────────────────────────────────────────────────────────

def port_scan(host: str, ports: str = "top100", args: str = "") -> dict:
    """
    用 nmap 扫描目标端口。
    ports: 'top100'|'top1000'|'all'|'80,443,8080'|'1-65535'
    返回开放端口列表和服务信息。
    """
    try:
        import nmap
    except ImportError:
        return {"error": "python-nmap 未安装，运行: pip install python-nmap"}

    nm = nmap.PortScanner(nmap_search_path=(NMAP_BIN,))
    port_arg = {
        "top100":  "--top-ports 100",
        "top1000": "--top-ports 1000",
        "all":     "-p-",
    }.get(ports, f"-p {ports}")

    scan_args = f"-sV -T4 {port_arg} {args}"
    logger.info("nmap 扫描: %s %s", host, scan_args)

    try:
        nm.scan(hosts=host, arguments=scan_args)
    except Exception as e:
        return {"error": str(e)}

    results = []
    for h in nm.all_hosts():
        for proto in nm[h].all_protocols():
            for port in sorted(nm[h][proto].keys()):
                info = nm[h][proto][port]
                if info["state"] == "open":
                    results.append({
                        "port": port,
                        "protocol": proto,
                        "state": info["state"],
                        "service": info.get("name", ""),
                        "version": info.get("version", ""),
                        "product": info.get("product", ""),
                        "extrainfo": info.get("extrainfo", ""),
                    })

    return {
        "host": host,
        "open_ports": results,
        "total_open": len(results),
        "summary": [f"{r['port']}/{r['protocol']} {r['service']} {r['product']} {r['version']}".strip()
                    for r in results],
    }


# ── 目录爆破 ──────────────────────────────────────────────────────────────────

def dir_fuzz(
    url: str,
    wordlist: str = "common",
    extensions: str = "",
    threads: int = 50,
    timeout: int = 90,
    extra_args: str = "",
) -> dict:
    """
    用 ffuf 爆破目录/文件。
    url: 目标URL，如 http://target.com/FUZZ 或 http://target.com/（自动加FUZZ）
    wordlist: 'common'|'big'|'api'|'/path/to/custom.txt'
    extensions: 逗号分隔，如 'php,html,txt'
    """
    if not os.path.exists(FFUF_BIN):
        return {"error": f"ffuf 未找到: {FFUF_BIN}"}

    # 确保 URL 含 FUZZ
    if "FUZZ" not in url:
        url = url.rstrip("/") + "/FUZZ"

    # 选择字典
    wl_map = {
        "common": str(_WORDLISTS / "common.txt"),
        "big":    str(_WORDLISTS / "big.txt"),
        "api":    str(_WORDLISTS / "api-endpoints.txt"),
    }
    wl_path = wl_map.get(wordlist, wordlist)
    if not os.path.exists(wl_path):
        return {"error": f"字典不存在: {wl_path}，可用: common/big/api 或绝对路径"}

    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as tf:
        out_file = tf.name

    cmd = [
        FFUF_BIN, "-u", url, "-w", wl_path,
        "-t", str(threads),
        "-o", out_file, "-of", "json",
        "-mc", "200,201,204,301,302,307,401,403,405",
        "-x", PROXY,
        "-s",  # silent
    ]
    if extensions:
        cmd += ["-e", "." + extensions.replace(",", ",.")]
    if extra_args:
        cmd += extra_args.split()

    logger.info("ffuf: %s", " ".join(cmd[:6]) + "...")
    stdout, stderr, rc = _run(cmd, timeout=timeout)

    results = []
    try:
        with open(out_file) as f:
            data = json.load(f)
        for r in data.get("results", []):
            results.append({
                "url":    r.get("url", ""),
                "status": r.get("status", 0),
                "length": r.get("length", 0),
                "words":  r.get("words", 0),
                "lines":  r.get("lines", 0),
            })
    except Exception:
        pass
    finally:
        try:
            os.unlink(out_file)
        except Exception:
            pass

    return {
        "target": url,
        "wordlist": wordlist,
        "found": results,
        "total": len(results),
        "summary": [f"{r['status']} {r['url']}" for r in results[:30]],
    }


# ── 子域名枚举 ────────────────────────────────────────────────────────────────

def subdomain_enum(domain: str, timeout: int = 60) -> dict:
    """用 subfinder 枚举子域名"""
    if not os.path.exists(SUBFINDER_BIN):
        return {"error": f"subfinder 未找到: {SUBFINDER_BIN}"}

    cmd = [SUBFINDER_BIN, "-d", domain, "-silent", "-timeout", "30"]
    logger.info("subfinder: %s", domain)
    stdout, stderr, rc = _run(cmd, timeout=timeout)

    subdomains = [s.strip() for s in stdout.splitlines() if s.strip()]
    return {
        "domain": domain,
        "subdomains": subdomains,
        "total": len(subdomains),
    }


# ── HTTP 探测 ─────────────────────────────────────────────────────────────────

def http_probe(targets: list[str] | str, timeout: int = 30) -> dict:
    """
    用 httpx 批量探测 URL/IP 列表，返回存活的 HTTP 服务。
    targets: URL列表 或 换行分隔的字符串
    """
    if not os.path.exists(HTTPX_BIN):
        return {"error": f"httpx 未找到: {HTTPX_BIN}"}

    if isinstance(targets, str):
        target_list = [t.strip() for t in targets.splitlines() if t.strip()]
    else:
        target_list = targets

    with tempfile.NamedTemporaryFile(suffix=".txt", delete=False, mode="w") as tf:
        tf.write("\n".join(target_list))
        in_file = tf.name

    cmd = [
        HTTPX_BIN, "-l", in_file,
        "-silent", "-json",
        "-title", "-tech-detect", "-status-code",
        "-timeout", "10",
        "-http-proxy", PROXY,
    ]
    logger.info("httpx probe: %d targets", len(target_list))
    stdout, stderr, rc = _run(cmd, timeout=timeout)

    results = []
    for line in stdout.splitlines():
        try:
            r = json.loads(line)
            results.append({
                "url":    r.get("url", ""),
                "status": r.get("status-code", 0),
                "title":  r.get("title", ""),
                "tech":   r.get("tech", []),
            })
        except Exception:
            pass

    try:
        os.unlink(in_file)
    except Exception:
        pass

    return {"results": results, "total": len(results)}


# ── JS 分析 ───────────────────────────────────────────────────────────────────

def analyze_js(html_or_js: str, base_url: str = "") -> dict:
    """
    从 HTML 或 JS 内容中提取：
    - API 端点
    - 硬编码密钥/Token/密码
    - 内部 IP/域名
    """
    findings = {
        "api_endpoints": [],
        "secrets": [],
        "internal_hosts": [],
        "js_files": [],
    }

    # 提取 JS 文件引用
    js_refs = re.findall(r'src=["\']([^"\']*\.js[^"\']*)["\']', html_or_js, re.IGNORECASE)
    for ref in js_refs:
        if base_url and not ref.startswith("http"):
            from urllib.parse import urljoin
            ref = urljoin(base_url, ref)
        findings["js_files"].append(ref)

    # 提取 API 端点
    api_patterns = [
        r'["\`](/api/[^\s"\'`<>]{3,80})',
        r'["\`](/v\d+/[^\s"\'`<>]{3,80})',
        r'fetch\(["\`]([^"\'`]+)["\`]',
        r'axios\.[a-z]+\(["\`]([^"\'`]+)["\`]',
        r'url:\s*["\`]([^"\'`]+)["\`]',
        r'endpoint["\s]*[:=]["\s]*["\`]([^"\'`\s]{5,80})["\`]',
    ]
    seen = set()
    for pat in api_patterns:
        for m in re.finditer(pat, html_or_js, re.IGNORECASE):
            ep = m.group(1).strip()
            if ep not in seen and len(ep) > 3:
                seen.add(ep)
                findings["api_endpoints"].append(ep)

    # 提取硬编码密钥
    secret_patterns = [
        (r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "api_key"),
        (r'(?:secret|token|password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']', "secret"),
        (r'(?:aws_access_key_id|aws_secret)\s*[=:]\s*["\']([A-Z0-9]{16,})["\']', "aws_key"),
        (r'eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}', "jwt"),
        (r'(?:Authorization|Bearer)\s*[=:]\s*["\']([^"\']{10,})["\']', "auth_header"),
    ]
    for pat, kind in secret_patterns:
        for m in re.finditer(pat, html_or_js, re.IGNORECASE):
            val = m.group(1) if m.lastindex else m.group(0)
            findings["secrets"].append({"type": kind, "value": val[:80]})

    # 提取内网 IP/域名
    internal_patterns = [
        r'\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3})\b',
        r'\b(172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b',
        r'\b(192\.168\.\d{1,3}\.\d{1,3})\b',
        r'\b(localhost:\d+)\b',
        r'["\']([a-z0-9\-]+\.internal[^"\']*)["\']',
    ]
    seen_hosts = set()
    for pat in internal_patterns:
        for m in re.finditer(pat, html_or_js, re.IGNORECASE):
            h = m.group(1)
            if h not in seen_hosts:
                seen_hosts.add(h)
                findings["internal_hosts"].append(h)

    return {
        "api_endpoints": findings["api_endpoints"][:50],
        "secrets":       findings["secrets"][:20],
        "internal_hosts": findings["internal_hosts"][:20],
        "js_files":      findings["js_files"][:30],
        "summary": {
            "api_count":      len(findings["api_endpoints"]),
            "secret_count":   len(findings["secrets"]),
            "internal_count": len(findings["internal_hosts"]),
            "js_file_count":  len(findings["js_files"]),
        },
    }

