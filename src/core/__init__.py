"""数据模型定义"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


class TestStatus(str, Enum):
    PENDING = "⏳待测"
    SAFE = "✅安全"
    VULNERABLE = "❌存在漏洞"
    SKIPPED = "⏭️跳过"
    NEEDS_REVIEW = "🔄需深入"


class Priority(str, Enum):
    P0 = "P0-无需认证"
    P1 = "P1-输入拼接"
    P2 = "P2-资源ID"
    P3 = "P3-文件操作"
    P4 = "P4-其他"


class VulnType(str, Enum):
    SQLI = "SQL注入"
    IDOR = "水平越权"
    VERTICAL_AUTHZ = "垂直越权"
    UNAUTH = "未授权访问"
    SSTI = "模板注入"
    RCE = "远程命令执行"
    FILE_UPLOAD = "文件上传"
    INFO_LEAK = "信息泄露"
    LOGIC = "逻辑漏洞"
    SSRF = "SSRF"
    XSS = "XSS"


@dataclass
class Parameter:
    name: str
    location: str  # query / body / header / cookie / path
    param_type: str = "string"
    required: bool = False
    example: Any = None


@dataclass
class Endpoint:
    path: str
    method: HttpMethod
    parameters: list[Parameter] = field(default_factory=list)
    auth_required: bool = True
    description: str = ""
    priority: Priority = Priority.P4
    test_status: TestStatus = TestStatus.PENDING
    vulnerabilities: list[Vulnerability] = field(default_factory=list)


@dataclass
class Vulnerability:
    vuln_type: VulnType
    endpoint: str
    method: str
    parameter: str
    severity: str  # 严重 / 高 / 中 / 低
    description: str
    poc: str = ""
    request: str = ""
    response_snippet: str = ""
    exploitable: bool = False
    constraints: str = ""


@dataclass
class AgentMessage:
    """Agent间通信消息"""
    sender: str
    receiver: str
    msg_type: str  # endpoints / test_plan / result / feedback
    payload: Any = None
