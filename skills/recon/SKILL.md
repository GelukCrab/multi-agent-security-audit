---
name: recon
description: 目标侦察与攻击面枚举
tags: recon, fingerprint, port, directory, subdomain, js-analysis
priority: 100
phase: recon
chain: recon -> exploit -> post-exploit
author: multi-agent-security-audit
---

# 侦察技能

## 阶段定义
侦察是渗透测试的第一步，目标是全面了解目标的技术栈、攻击面和潜在入口。

## 侦察清单

### Web指纹识别
- Server响应头(Apache/Nginx/IIS/Tomcat)
- X-Powered-By(PHP/ASP.NET/Express)
- Set-Cookie特征(PHPSESSID/JSESSIONID/ASP.NET_SessionId)
- 框架特征(Laravel/Django/Spring Boot/ThinkPHP)

### 攻击面枚举
- 页面表单(登录/注册/搜索/上传)
- URL参数(id/page/sort/search/file)
- API接口(/api/ /v1/ /v2/)
- 管理后台(/admin /manage /console)

### 信息泄露探测
- .git/HEAD
- .env
- /swagger-ui.html
- /actuator
- /phpinfo.php
- robots.txt
- 备份文件(.bak .zip .tar.gz)

### JS分析
- API路径提取
- 硬编码密钥/Token
- 隐藏功能入口

## Strategy

1. fetch_page获取首页，分析响应头和页面内容
2. extract_forms提取所有表单
3. extract_links发现所有链接
4. 探测常见泄露路径
5. 根据指纹判断技术栈，选择对应exploit skill
