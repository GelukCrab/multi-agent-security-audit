---
name: webapp-auth-bypass
description: Web应用认证绕过与越权
tags: auth, bypass, idor, privilege-escalation, jwt, session, cookie
priority: 85
phase: exploit
chain: recon -> webapp-auth-bypass -> post-exploit
author: multi-agent-security-audit
---

# 认证绕过与越权技能

## 攻击向量

### 登录绕过
- SQL注入万能密码: admin' OR '1'='1
- 默认凭证: admin/admin, test/test
- 空密码/空用户名
- 响应篡改: 修改返回的status/code字段

### 水平越权(IDOR)
- 替换资源ID: /user/info?uid=1001 -> uid=1002
- 遍历自增ID
- UUID泄露检测

### 垂直越权
- 普通用户Cookie访问管理接口
- role/isAdmin参数可控
- 路径绕过: /admin -> /Admin -> /admin/ -> /admin;.js

### JWT/Token
- alg:none攻击
- 弱密钥爆破
- 算法混淆(RS256->HS256)
- payload篡改(role/uid)

### 未授权访问
- 删除Authorization头
- 常见未授权路径(/actuator /swagger /druid /nacos)

## Strategy

1. 先尝试默认凭证和弱口令
2. 测试登录接口SQL注入
3. 登录后测试越权(替换ID/角色)
4. 检查JWT/Token安全性
5. 探测未授权接口
