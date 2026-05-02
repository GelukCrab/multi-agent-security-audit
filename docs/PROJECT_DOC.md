# 多Agent协作智能渗透测试框架 — 项目文档

## 一、项目概述

基于LLM驱动的自主渗透测试框架，让AI作为主攻手自主完成从侦察到漏洞验证的完整渗透流程。区别于传统扫描器的"规则匹配"模式，本项目让大模型深度思考后自主决策攻击策略，具备自我进化能力。

**仓库地址**: https://github.com/GelukCrab/multi-agent-security-audit

**当前版本**: v1.6.0

---

## 二、已完成功能

### 2.1 核心架构：两阶段调用

解决了DeepSeek推理模型思考模式与Function Calling不兼容的问题。

```
每轮循环:
  思考阶段(thinking=on)  → 深度推理分析目标，输出JSON工具调用指令
  执行阶段(thinking=off) → 关闭思考，执行Function Calling调用工具
  工具结果 → 喂回下一轮思考
```

**关键文件**: `src/agents/pentest_agent.py`, `src/llm/__init__.py`

### 2.2 多Agent协作

| Agent | 角色 | 触发条件 |
|-------|------|---------|
| 主攻手(PentestAgent) | LLM自主决策渗透流程 | 始终运行 |
| 顾问(AdvisorAgent) | 卡点纠偏，建议新方向 | Reflector L3/L4触发 |
| 反思器(Reflector) | L1-L4分级失败归因 | 连续5次失败 |

**关键文件**: `src/agents/pentest_agent.py`, `src/agents/advisor_agent.py`, `src/core/reflector.py`

### 2.3 工具集（8个）

主攻手通过function calling调用：

| 工具 | 功能 |
|------|------|
| `fetch_page` | 获取页面HTML |
| `http_request` | 发送任意HTTP请求 |
| `extract_forms` | 提取表单和输入点 |
| `extract_links` | 提取链接 |
| `search_in_response` | 正则搜索响应内容 |
| `diff_responses` | 对比响应差异(布尔盲注) |
| `get_payloads` | 获取payload模板库 |
| `record_finding` | 记录漏洞(含完整HTTP复现数据包) |

**关键文件**: `src/tools/http_tools.py`, `src/tools/analysis_tools.py`, `src/tools/pentest_tools.py`

### 2.4 RAG向量知识库 + 经验自蒸馏

```
攻击成功 → LLM提炼经验(漏洞类型/目标特征/payload/绕过手法)
         → 向量化 → 写入ChromaDB
         → 下次攻击时语义检索 → 注入prompt
```

- 向量数据库: ChromaDB (本地持久化，`knowledge_db/`目录)
- Embedding模型: all-MiniLM-L6-v2 (本地ONNX，首次使用自动下载)
- 两个Collection: `attack_experience`(攻击经验), `cve_knowledge`(CVE知识)

**关键文件**: `src/knowledge/__init__.py`, `src/knowledge/distill.py`

### 2.5 Skill可插拔技能体系

三阶段技能编排: `recon → exploit → post-exploit`

```
skills/
├── recon/SKILL.md              # 侦察与攻击面枚举
├── webapp-sqli/SKILL.md        # SQL注入全链路(7类payload+WAF绕过)
├── webapp-auth-bypass/SKILL.md # 认证绕过与越权
├── ctf-web/SKILL.md            # CTF Web解题(8大题型)
├── post-exploit/SKILL.md       # 后渗透利用
├── intranet-pentest/SKILL.md   # 内网渗透与横向移动
└── ad-attack/SKILL.md          # AD域渗透攻击
```

技能通过Markdown SKILL.md定义，frontmatter声明元数据(name/tags/priority/phase/chain)，支持自动发现和按场景匹配。

**关键文件**: `src/core/skill_registry.py`

### 2.6 记忆系统

- 运行记忆: 当前审计实时状态
- 经验持久化: 按域名保存到`memory/`目录，相同目标再次审计自动加载
- 记录内容: 成功payload、失败路径、已验证攻击链

**关键文件**: `src/core/memory.py`

### 2.7 CTF模式

`--ctf` 参数切换，以找flag为核心目标：
- 每次响应自动搜索flag格式
- SQL注入后遍历所有表找flag字段
- RCE后优先 `cat /flag`
- 独立的CTF_SYSTEM_PROMPT

### 2.8 报告与日志

- 渗透报告: `reports/` 目录，支持JSON和Markdown格式
- 运行日志: `logs/` 目录，完整DEBUG记录(含LLM交互、token消耗)
- 报告包含完整HTTP复现数据包，可直接Burp/curl发包

---

## 三、测试成果

### sqli-labs靶场测试 (Less-1 ~ Less-65)

**通过率: 57/65 = 87.7%**

| 关卡范围 | 通过/总数 | 涉及技术 |
|---------|----------|---------|
| Less-1~10 | 10/10 | GET参数注入(单引号/双引号/括号/盲注) |
| Less-11~17 | 7/7 | POST表单注入(报错/盲注/UPDATE注入) |
| Less-18~22 | 5/5 | Header注入(UA/Referer/Cookie/Base64) |
| Less-23~28 | 6/6 | 过滤绕过(注释/双写/空格/关键字) |
| Less-29~31 | 3/3 | HPP/双引号/括号闭合 |
| Less-32~37 | 6/6 | 宽字节注入(addslashes/mysql_real_escape_string) |
| Less-38~45 | 8/8 | 堆叠查询(Stacked Query) |
| Less-46~53 | 6/8 | ORDER BY注入 |
| Less-54~65 | 6/12 | Challenge限制次数模式 |

未通过的8关主要是Challenge模式(限制尝试次数)的盲注关卡。

### CTF实战

- ctf.show Web入门题: 成功找到flag(HTML注释泄露 + PHP eval命令执行绕过)

---

## 四、技术栈

| 组件 | 技术 |
|------|------|
| LLM | DeepSeek v4-pro(主攻手) + v4-flash(顾问) |
| API协议 | OpenAI兼容(支持DeepSeek/GPT/通义等) |
| 向量数据库 | ChromaDB + all-MiniLM-L6-v2 |
| HTTP客户端 | httpx(异步，支持SOCKS5代理) |
| 配置 | YAML + .env环境变量 |
| 日志 | Python logging(控制台+文件双输出) |

---

## 五、项目结构

```
multi-agent-security-audit/
├── src/
│   ├── agents/
│   │   ├── pentest_agent.py     # LLM主攻手(两阶段调用+CTF模式)
│   │   └── advisor_agent.py     # 顾问Agent
│   ├── llm/
│   │   └── __init__.py          # LLM Provider(think/execute/chat)
│   ├── tools/
│   │   ├── http_tools.py        # HTTP请求工具
│   │   ├── analysis_tools.py    # 页面分析工具
│   │   └── pentest_tools.py     # 渗透辅助工具
│   ├── core/
│   │   ├── orchestrator.py      # 调度器
│   │   ├── reflector.py         # L1-L4失败归因
│   │   ├── memory.py            # 运行记忆+经验持久化
│   │   ├── skill_registry.py    # 技能注册(phase/chain)
│   │   └── report.py            # 报告生成
│   ├── knowledge/
│   │   ├── __init__.py          # ChromaDB向量知识库
│   │   └── distill.py           # 经验自蒸馏
│   ├── utils/
│   │   ├── http_client.py       # 代理感知HTTP客户端
│   │   ├── payload_db.py        # Payload模板库
│   │   ├── fingerprint.py       # 框架指纹识别
│   │   └── display.py           # Rich控制台输出
│   └── main.py                  # 入口
├── skills/                      # 可插拔技能(7个)
├── config/default.yaml          # 默认配置
├── CLAUDE.md                    # Git提交规则
└── README.md
```

---

## 六、已知问题

1. **思考阶段偶发空响应**: DeepSeek API偶尔返回空，已有重试机制(max_empty_retries=3)，但极端情况仍可能提前退出
2. **Challenge模式效率**: 限制尝试次数的盲注场景，30轮内逐字符提取效率不够
3. **Skill未注入prompt**: 当前skill体系已建好但skill内容还没有自动注入到主攻手的system prompt中，模型靠自身知识决策
4. **知识库冷启动**: 首次使用需下载79MB的embedding模型，需要代理

---

## 七、后续规划

### 7.1 短期优化

- [ ] **Skill自动注入**: 根据目标特征自动匹配skill，将相关skill内容注入system prompt
- [ ] **并行请求**: 一轮内支持多个HTTP请求并行发送，提升盲注效率
- [ ] **CVE知识库填充**: 批量导入NVD/CNVD的CVE数据，支持按产品/版本检索已知漏洞
- [ ] **多模型支持**: 支持在config中配置不同模型(如主攻手用Claude，顾问用DeepSeek)

### 7.2 中期扩展

- [ ] **内网渗透工具链**: 集成fscan/frp/chisel等工具的调用能力，支持隧道搭建和内网扫描
- [ ] **域渗透工具链**: 集成impacket/Rubeus/BloodHound等，支持Kerberoasting/ADCS攻击/DCSync
- [ ] **全链路作战单元**: 实现 侦察→武器化→投递→利用→持久化 的完整Kill Chain
- [ ] **多Agent并发**: 多个主攻手同时攻击不同目标/不同攻击面

### 7.3 长期愿景

- [ ] **Web Dashboard**: FastAPI + SSE实时推送，可视化攻击过程和知识库
- [ ] **自动化靶场训练**: 对接VulnHub/HackTheBox等靶场，自动刷题积累经验
- [ ] **红队协作**: 多Agent分工(侦察Agent/漏洞利用Agent/后渗透Agent)，模拟真实红队作战
- [ ] **对抗学习**: 蓝队Agent防守 vs 红队Agent攻击，通过对抗提升双方能力

---

## 八、使用方式

### 安装
```bash
pip install -r requirements.txt
```

### 配置API Key
```bash
# 在项目根目录创建.env
echo "DEEPSEEK_API_KEY=你的key" > .env
```

### 运行
```bash
# 渗透模式
python -m src.main -t http://目标地址

# CTF模式
python -m src.main -t http://目标地址 --ctf

# 详细日志
python -m src.main -t http://目标地址 -v

# 指定报告格式
python -m src.main -t http://目标地址 -f markdown
```

### 版本历史

| 版本 | 说明 |
|------|------|
| v1.0.0 | 初始版本(规则扫描器架构) |
| v1.1.0 | LLM驱动架构重构 |
| v1.2.0 | 全面审计批量修复 |
| v1.3.0 | 两阶段调用架构(思考+执行) |
| v1.4.0 | URL编码/报告格式/漏洞记录修复 |
| v1.4.1 | 空决策重试增强 |
| v1.5.0 | 专业化skill体系(6个skill) |
| v1.5.1 | 域渗透+内网渗透skill |
| v1.5.2 | CTF Web解题skill |
| v1.6.0 | RAG向量知识库 + 经验自蒸馏 + CTF模式 |
