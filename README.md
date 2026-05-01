# 多Agent协作智能渗透测试框架

基于LLM驱动的自主渗透测试框架，让AI作为主攻手自主完成从侦察到漏洞验证的完整渗透流程。

## 架构

```
┌─────────────────────────────────────────────────────────┐
│                    调度器 Orchestrator                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  ┌───────────────────────────────────────────────────┐  │
│  │            主攻手 PentestAgent                     │  │
│  │                                                   │  │
│  │   思考阶段(thinking=on)    执行阶段(thinking=off) │  │
│  │   ┌─────────────────┐     ┌──────────────────┐   │  │
│  │   │ 深度推理分析目标 │────▶│ Function Calling │   │  │
│  │   │ 制定攻击策略    │     │ 执行工具调用     │   │  │
│  │   │ 构造payload     │◀────│ 返回执行结果     │   │  │
│  │   └─────────────────┘     └──────────────────┘   │  │
│  └───────────────────────────────────────────────────┘  │
│                         │                               │
│            连续失败触发 ▼                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐  │
│  │ 反思器       │  │ 顾问Agent    │  │ 记忆系统     │  │
│  │ L1-L4归因   │─▶│ 策略纠偏     │  │ 经验持久化   │  │
│  └──────────────┘  └──────────────┘  └──────────────┘  │
└─────────────────────────────────────────────────────────┘
```

## 核心特性

- **LLM自主决策**: 模型作为主攻手，自主分析目标、构造payload、验证漏洞
- **两阶段调用**: 思考模式深度推理 + 执行模式调用工具，兼顾推理质量和工具能力
- **顾问纠偏**: 主攻手卡住时由Reflector触发顾问Agent介入，防止重复犯错
- **经验记忆**: 按目标域名持久化审计经验，相同目标再次测试时自动加载
- **可插拔技能**: 基于Markdown定义的技能系统，新增检测能力无需改代码

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置API Key

在项目根目录创建 `.env` 文件：

```env
DEEPSEEK_API_KEY=你的key
```

### 3. 运行

```bash
# 对目标执行渗透测试
python -m src.main -t http://目标地址:端口/路径

# 带详细日志
python -m src.main -t http://目标地址:端口/路径 -v

# 指定报告格式
python -m src.main -t http://目标地址:端口/路径 -f markdown
```

## 工具集

主攻手拥有以下工具：

| 工具 | 功能 |
|------|------|
| `fetch_page` | 获取页面HTML内容 |
| `http_request` | 发送任意HTTP请求 |
| `extract_forms` | 从HTML提取表单和输入点 |
| `extract_links` | 从HTML提取链接 |
| `search_in_response` | 正则搜索响应内容 |
| `diff_responses` | 对比两个响应差异(布尔盲注) |
| `get_payloads` | 获取payload模板库 |
| `record_finding` | 记录已确认的漏洞 |

## 项目结构

```
src/
├── agents/
│   ├── pentest_agent.py     # LLM主攻手(两阶段调用)
│   └── advisor_agent.py     # 顾问Agent(卡点纠偏)
├── llm/
│   └── __init__.py          # LLM Provider(think/execute/chat)
├── tools/
│   ├── http_tools.py        # HTTP请求工具
│   ├── analysis_tools.py    # 页面分析工具
│   └── pentest_tools.py     # 渗透辅助工具
├── core/
│   ├── orchestrator.py      # 调度器
│   ├── reflector.py         # L1-L4失败归因反思器
│   ├── memory.py            # 运行记忆+经验持久化
│   ├── skill_registry.py    # 可插拔技能注册
│   └── report.py            # 报告生成
├── utils/
│   ├── http_client.py       # 代理感知HTTP客户端
│   ├── payload_db.py        # Payload模板库
│   └── fingerprint.py       # 框架指纹识别
└── main.py                  # 入口
config/
└── default.yaml             # 默认配置
skills/
└── webapp-sqli/SKILL.md     # 示例技能定义
```

## 配置说明

`config/default.yaml` 主要配置项：

```yaml
llm:
  base_url: "https://api.deepseek.com"
  main_model: "deepseek-v4-pro"      # 主攻手模型
  advisor:
    model: "deepseek-v4-flash"       # 顾问模型

agents:
  pentest:
    max_rounds: 30                   # 最大推理轮次
```

API Key通过环境变量或 `.env` 文件设置，不要写在配置文件里。

## 日志与报告

- 运行日志: `logs/audit_时间戳.log` (完整DEBUG记录)
- 渗透报告: `reports/audit_时间戳.md` (漏洞详情+PoC)
- 审计经验: `memory/域名.json` (持久化经验)

## 许可证

MIT
