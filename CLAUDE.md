# CLAUDE.md

## Git 提交规则

### 提交时机
- **不要逐个bug提交**，累积修改后统一提交
- 满足以下任一条件时提交：
  1. 累积了 5 个以上的 bug 修复
  2. 完成了一个完整功能或模块
  3. 架构级改动（影响多个模块的重构）
  4. 用户明确要求提交
  5. 当前工作告一段落（如测试通过、准备切换任务）

### 版本号规则 (v1.Y.Z)
- 整个项目生命周期保持 v1.x.x
- **v1.Y.0** — 架构级改动、新增重要功能模块
- **v1.y.Z** — bug 修复、小改进、配置调整
- 不要为每个小修复单独打 tag，多个修复合并为一个版本

### 提交信息格式
- tag标题简洁，但commit message必须详细列出每一项改动
- 每个修复/改进单独一行，说清楚：改了什么文件、修了什么问题、为什么改
- 格式：
```
v1.x.x 简要标题

修复:
- [文件名] 具体修了什么问题（触发条件/现象）
- [文件名] 具体修了什么问题

增强:
- [文件名] 新增了什么功能/改进了什么
```
- 示例：
```
v1.4.0 修复URL编码/报告格式/漏洞记录等问题

修复:
- [http_tools.py] URL中%0a/%09等非打印字符保留编码，修复httpx报Illegal header错误
- [pentest_tools.py] record_finding的request_headers参数支持dict类型，修复'dict has no rstrip'报错
- [report.py] severity统计同时匹配中英文(严重/critical)，修复发现漏洞但概览显示0
- [report.py] 数据包\r\n转\n，修复markdown渲染成双换行
- [pentest_agent.py] 思考阶段空输出重试2次而非直接退出，修复Less-16漏洞发现但未记录
- [pentest_agent.py] 模型试图结束但未记录漏洞时强制提醒补录

增强:
- [pentest_tools.py] record_finding新增request_url/request_headers/request_body，报告输出完整HTTP复现数据包
- [pentest_agent.py] system prompt强制中文输出，severity改为中文(严重/高/中/低)
```

### 分支策略
- 直接在 main 分支开发
- 每次 push 前确保代码能正常运行（至少 --help 不报错）
- push 需要走代理: `git -c http.proxy=http://127.0.0.1:7890 -c https.proxy=http://127.0.0.1:7890 push origin main`

### 敏感信息
- API key 通过 .env 文件配置，绝对不能写进代码或配置文件
- .env 已在 .gitignore 中
- 提交前检查 config/default.yaml 中 api_key 字段是否为空

## 项目约定

### 测试验证
- 代码修改后先做语法检查再提交
- 重要修改需要实际运行验证（不只是语法通过）

### 日志
- 运行日志在 logs/ 目录
- 报告在 reports/ 目录
- 两者都在 .gitignore 中，不提交
