# 这是一个可以帮完全不懂编程的vibecoding人员，静态审计项目，重建项目wiki和各模块文档的工具，可以通过MCP对接你的编程AI。
This is a tool designed to help vibecoding personnel with no programming background statically audit projects, rebuild project wikis, and document each module, and it can connect with your programming AI through MCP.

# CodeRef AI — 编程 AI 外置大脑 & 非编程人员技术助理

**Version 3.1** | Python 3.10+ | MCP Protocol | Apache 2.0

> 一键审计 · 架构图谱 · 项目文档 · 知识图谱 · 健康仪表盘

---

## 一句话定位

CodeRef AI 是**编程 AI 的外置大脑**和**非编程人员的技术助理**。它通过 MCP 协议暴露 6 个工具，让 AI 编程助手不需要逐文件读代码，而是像查数据库一样查询项目结构和风险；同时生成非技术人员也能看懂的项目健康仪表盘和 Wiki 文档。

## 为什么需要 CodeRef

| 痛点 | CodeRef 怎么解决 |
|------|-----------------|
| AI 逐文件读代码产生幻觉，遗漏关键信息 | 11 个独立检测工具交叉验证，置信度分级，消除 AI 自查幻觉 |
| 审计报告海量误报，人工筛选耗时 | 三级自动降噪，实测 321 条 → 13 条（95.9% 降幅） |
| AI 每次都要 grep/读文件才能理解项目 | 知识图谱持久化，结构化查询代替逐文件阅读，节省 10-100 倍 token |
| 非技术人员完全看不懂代码 | 一键生成通俗 Wiki + 健康仪表盘 HTML，零技术门槛 |
| 安全漏洞、技术债务默默积累无人发现 | 全维度审计，覆盖 11 个维度，持续监控项目健康 |

## 核心能力一览

| 能力 | 面向谁 | 工具 | 说明 |
|------|--------|------|------|
| 全维度代码审计 | 编程 AI + 开发者 | `coderef_audit` | 11 个检测工具一次运行，三级自动降噪，交叉验证 |
| 知识图谱查询 | 编程 AI | `coderef_query` | 9 种查询类型，结构化项目记忆层，替代 grep/读文件 |
| 架构分析图谱 | 开发者 | `coderef_architecture` | 交互式 HTML 模块画布（vis-network），可视化模块关系 |
| 项目 Wiki 文档 | 非编程人员 | `coderef_docs` | 三级管线生成，通俗语言解释项目结构，支持子项目探测 |
| 健康仪表盘 | 非编程人员 | （审计自动产出） | 一个 HTML 页面看懂安全评分、债务评分、风险清单 |
| 误报管理 | 开发者 | `coderef_whitelist` | 白名单管理 + 核心模块规则配置，持续优化审计精度 |

## 快速开始

### 1. 安装

```bash
git clone https://github.com/your-org/coderef-ai.git
cd coderef-ai
pip install -r requirements.txt
```

### 2. 配置 LLM（可选）

> 审计和知识图谱功能**不需要 LLM**，纯静态分析即可运行。仅 Wiki 文档生成（`coderef_docs`）需要 LLM。

**Windows 用户：**

```bash
setup.bat
```

**Linux / macOS 用户：**

```bash
export CODEREF_API_KEY="your-api-key"
export CODEREF_PROVIDER="deepseek"        # 支持: deepseek / openai / ollama
export CODEREF_BASE_URL="https://api.deepseek.com/v1"
export CODEREF_MODEL="deepseek-chat"
```

**使用本地 Ollama（免费，无需 API Key）：**

```bash
export CODEREF_PROVIDER="ollama"
export CODEREF_BASE_URL="http://localhost:11434/v1"
export CODEREF_MODEL="qwen2.5:7b"
export CODEREF_API_KEY="ollama"
```

### 3. 启动 MCP Server

```bash
python -m core.mcp_server
```

### 4. 配置 MCP 客户端

在 Trae / Claude Desktop 等 MCP 客户端中添加：

```json
{
  "mcpServers": {
    "coderef-ai": {
      "command": "python",
      "args": ["-m", "core.mcp_server"],
      "cwd": "/path/to/coderef-ai"
    }
  }
}
```

详细配置指南见 [MCP_SETUP.md](MCP_SETUP.md)。

## 6 个 MCP 工具

| 工具 | 功能 | 模式 | 需要 LLM |
|------|------|------|---------|
| `coderef_audit` | 11 审计工具一键产出 + 自动降噪 + 知识图谱构建 | 后台 | 否 |
| `coderef_architecture` | 架构分析图谱 + 交互式 HTML 模块画布 | 同步 | 否 |
| `coderef_docs` | 项目 Wiki 文档生成 + 子项目探测 | 后台 | 是 |
| `coderef_query` | 知识图谱结构化查询（9 种查询类型） | 同步 | 否 |
| `coderef_whitelist` | 白名单管理 + 核心模块规则配置 | 同步 | 否 |
| `coderef_task_status` | 后台任务状态查询 | 同步 | 否 |

## 典型使用流程

```
# 1. 初次分析：跑一次审计（自动构建知识图谱）
coderef_audit(project_path="/path/to/project", background=True)
coderef_task_status(task_id="...")

# 2. 编程 AI 随时查询知识图谱（替代 grep/读文件）
coderef_query(project_path="/path/to/project", query_type="callers", func_name="login")
coderef_query(project_path="/path/to/project", query_type="impact", file_path="utils.py")

# 3. 生成项目文档（非编程人员阅读）
coderef_docs(project_path="/path/to/project", background=True)

# 4. 查看健康仪表盘
# → coderef-report/health_dashboard_{timestamp}.html

# 5. 直接询问你的编程AI：请你阅读这个项目的报告，把漏报写进白名单，把问题归类为4种（①你可以自行处理 ②需要我介入 ③很复杂或者很严重，需要我参与讨论 ④新建一个暂存区，看看是误报还是真没有意义需要删除的东西）
# → coderef-report/health_dashboard_{timestamp}.html
```


## 审计管线

### 11 个检测工具

| 检测器 | 检测内容 |
|--------|---------|
| 治理审计 (gov) | 架构违规、安全漏洞、反模式、质量铁律，CWE/OWASP 映射 |
| Agent 安全审计 (agent) | 提示注入、上下文操纵、工具滥用、数据泄露、自主行为 |
| 依赖扫描 (sca) | requirements.txt / pyproject.toml 的 CVE 漏洞 |
| 技术债务 (td) | 圈复杂度、认知复杂度、过长函数、魔法数字、注释代码 |
| 完整性检查 (integ) | TODO/FIXME 残留、孤立测试文件、文档覆盖率 |
| 盲区检测 (blind) | 文档盲区、缺失依赖、动态路径注入、空文件 |
| 创新传播 (inn) | 模块间设计模式不一致、"A 有 B 该有但没有"的缺口 |
| 垃圾文件 (junk) | 重复文件、应被 gitignore 的文件、孤立文件 |
| 资源遗漏 (resgap) | 缺失本地模块、动态导入风险、未使用依赖 |
| 代码精简 (simp) | 死代码、可标准库替代、过度工程 |
| 项目成熟度 (matu) | 项目健康度综合评分 |

### 三级自动降噪

| 层级 | 机制 | 效果 |
|------|------|------|
| Layer 1 | AI 白名单（`coderef_whitelist` 写入） | 精准抑制已知误报 |
| Layer 2 | NOISE_RULES 规则匹配 | 自动抑制 MD5 哈希、配置 URL 等常见误报 |
| Layer 3 | 合并汇总 | 邻行去重 + 爆发式汇总（>8 条同类别 → 1 条统计） |

### 交叉验证反幻觉

多工具独立分析同一项目，相互验证结果，产生置信度分级（HIGH / MEDIUM / LOW）。这是 CodeRef 对抗 AI 自查幻觉的核心机制——单一工具可能误判，但多个独立工具交叉验证后，置信度大幅提升。

## 知识图谱

运行 audit / architecture / docs 后自动构建 SQLite 知识图谱，持久化到 `cache/kg/`。一次构建，跨会话复用。

**查询速查：**

| 想知道什么 | query_type | 参数 |
|-----------|-----------|------|
| 项目有多大 | `stats` | 无 |
| 搜索包含 "auth" 的代码 | `search` | `keyword="auth"` |
| 查找所有认证相关函数 | `entity` | `name="auth", type="function"` |
| 谁调用了 `process_order` | `callers` | `func_name="process_order"` |
| `main` 调用了哪些函数 | `callees` | `func_name="main"` |
| 修改 `utils.py` 影响哪些模块 | `impact` | `file_path="utils.py"` |
| `server.py` 有哪些函数和类 | `file_entities` | `file_path="server.py"` |
| 从 `handle_request` 展开调用链 | `call_graph` | `func_name="handle_request", depth=3` |

**实体类型：** `module` / `function` / `class` / `method` / `config` / `constant`  
**关系类型：** `CONTAINS` / `IMPORTS` / `INHERITS` / `CALLS` / `REFERENCES`

## 项目结构

```
coderef-ai/
├── core/                              # 核心模块
│   ├── mcp_server.py                  # MCP Server 入口（6 个工具）
│   ├── pipeline_runner.py             # 管线引擎（audit/architecture/docs + 知识图谱）
│   ├── code_knowledge_graph.py        # 知识图谱引擎（SQLite 持久化）
│   ├── health_dashboard.py            # 项目健康仪表盘（零外部依赖 HTML）
│   ├── wiki_generator.py              # Wiki 生成器（三级管线）
│   ├── code_analyzer.py               # 代码分析引擎（AST）
│   ├── ast_parser.py                  # AST 精细解析器（调用关系/赋值/配置）
│   ├── workflow_graph.py              # 架构图生成器（vis-network）
│   ├── shared_filter.py               # 通用过滤基础设施（AutoNoiseFilter）
│   ├── project_scope.py               # 项目范围管理
│   ├── llm_integration.py             # LLM 集成（多模型支持）
│   ├── cache_manager.py               # 缓存管理
│   ├── gitnexus_client.py             # GitNexus 客户端
│   ├── governance_audit.py            # 11 个检测器
│   ├── agent_security_auditor.py
│   ├── sca_checker.py
│   ├── tech_debt_detector.py
│   ├── integrity_checker.py
│   ├── blind_spot_detector.py
│   ├── innovation_propagation_detector.py
│   ├── junk_detector.py
│   ├── resource_gap_detector.py
│   ├── code_simplifier.py
│   └── project_maturity_checker.py
├── config/                            # 配置文件
│   └── settings.py
├── utils/                             # 工具函数
│   └── helpers.py
├── cache/                             # 运行时缓存（.gitignore 已忽略）
├── coderef-report/                    # 输出报告（.gitignore 已忽略）
├── setup.bat                          # Windows 配置向导
├── requirements.txt
├── MCP_SETUP.md                       # 详细配置指南
└── LICENSE
```

## 设计特性

| 特性 | 说明 |
|------|------|
| 不修改代码 | 所有建议只输出不执行，原代码保持不变 |
| 本地优先 | 代码分析完全在本地，审计和知识图谱无需网络，支持离线运行 |
| 隐私安全 | LLM API 密钥存本地 `cache/`，不提交 Git |
| 结构化输出 | 报告 Markdown，仪表盘 HTML，知识图谱 SQLite |
| 检查点续跑 | 管线每 2 分钟保存进度，中断后可恢复 |
| 后台任务 | 长任务（audit / docs）异步执行，轮询获取结果 |
| 项目隔离 | 每个项目独立缓存，切换项目不互相干扰 |
| 开源友好 | 敏感数据集中 `cache/`，删除即清理，一行命令安全开源 |

## 更新日志

### v3.1 — 知识图谱 + 健康仪表盘

- 新增 SQLite 持久化项目知识图谱，6 种节点类型，6 种关系边
- 新增 `coderef_query` MCP 工具，9 种查询类型，替代 grep / 读文件
- 新增零外部依赖 HTML 健康仪表盘，非编程人员友好
- AstParser 集成到知识图谱构建，自动填充 CALLS 边
- Wiki 核心模块判定规则可配置化（`coderef_whitelist` 扩展）
- `coderef_whitelist` 新增 `core_rules_get / set / reset` 操作

### v3.0 — 三功能管线架构

- 18 个独立 MCP 工具 → 合并为 3 个管线（audit / architecture / docs）
- 统一管线引擎：共享 AST 扫描 + 检查点续跑 + 后台任务
- 三级自动降噪（AutoNoiseFilter）：白名单 + NOISE_RULES + 合并汇总
- 交叉验证：多工具独立分析互验，产生置信度分级

## 许可证

Apache License 2.0 — 详见 [LICENSE](LICENSE)。
