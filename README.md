# 多Agent协作安全审计框架

基于多Agent协作的AI驱动自动化安全审计框架，将渗透测试中"枚举-分析-验证"全流程交给协作Agent完成。

## 架构

```
┌─────────────┐     ┌──────────────┐     ┌───────────────┐
│  侦察 Agent │────▶│  分析 Agent  │────▶│  验证 Agent   │
│  (攻击面枚举)│     │ (威胁建模)   │     │  (漏洞验证)   │
└─────────────┘     └──────────────┘     └───────────────┘
       ▲                                        │
       └──────────── 反馈闭环 ──────────────────┘
```

**侦察Agent** — 攻击面发现：爬取前端JS、解析API文档(Swagger/OpenAPI)、枚举所有端点和参数。

**分析Agent** — 对每个端点进行威胁建模，基于参数语义、认证要求、框架指纹进行长链推理，推断漏洞类型并按风险优先级排序，输出测试计划。

**验证Agent** — 逐一构造验证请求，生成PoC载荷，分析响应差异，判断可利用性。结果实时反馈给分析Agent动态调整测试策略。

## 特性

- 全量API攻击面枚举，强制100%端点覆盖
- 长链推理识别业务逻辑漏洞
- 基于中间结果动态调整测试计划
- 结构化输出，每个端点有明确测试状态
- 支持SQL注入、越权、认证绕过、SSTI、文件上传、逻辑漏洞检测
- 代理感知的请求路由(SOCKS5/HTTP)

## 快速开始

```bash
pip install -r requirements.txt

# 对目标执行审计
python -m src.main --target https://example.com --config config/default.yaml

# 使用代理
python -m src.main --target https://example.com --proxy socks5://127.0.0.1:1080
```

## 项目结构

```
src/
├── agents/
│   ├── recon_agent.py       # 攻击面枚举
│   ├── analyzer_agent.py    # 威胁建模与优先级排序
│   └── exploit_agent.py     # 漏洞验证
├── core/
│   ├── orchestrator.py      # 多Agent调度协调
│   ├── message_bus.py       # Agent间通信
│   └── report.py            # 报告生成
├── utils/
│   ├── http_client.py       # 代理感知HTTP客户端
│   ├── payload_db.py        # Payload模板库
│   └── fingerprint.py       # 框架指纹识别
└── main.py                  # 入口
```

## 许可证

MIT
