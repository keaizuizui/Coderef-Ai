# CodeRef AI — MCP Server 配置指南

## 概述

CodeRef AI 通过 MCP (Model Context Protocol) 协议暴露 6 个工具给 AI 编程助手使用。配置一次后，AI 可以分析**任何项目**——每次调用时传入 `project_path` 参数即可，不需要重复配置。

**适用客户端：** Trae / Claude Desktop / Cursor / 任何支持 MCP 的 AI 编程助手

---

## 前置条件

- Python 3.10+
- （可选）LLM API Key —— 仅 Wiki 文档生成（`coderef_docs`）需要，审计和知识图谱无需 LLM

---

## 安装依赖

```bash
cd /path/to/coderef-ai
pip install -r requirements.txt
```

核心依赖：`tree-sitter`（代码解析）、`openai`（LLM 集成）、`loguru`（日志）、`pandas`（数据处理）。

---

## 配置 LLM（可选）

> 审计和知识图谱功能**不需要 LLM**，纯静态分析即可运行。仅 Wiki 文档生成需要 LLM。

### 方式一：环境变量（推荐）

**Linux / macOS：**

```bash
export CODEREF_API_KEY="your-api-key"
export CODEREF_PROVIDER="deepseek"        # 支持: deepseek / openai / ollama
export CODEREF_BASE_URL="https://api.deepseek.com/v1"
export CODEREF_MODEL="deepseek-chat"
```

**Windows PowerShell：**

```powershell
$env:CODEREF_API_KEY="your-api-key"
$env:CODEREF_PROVIDER="deepseek"
$env:CODEREF_BASE_URL="https://api.deepseek.com/v1"
$env:CODEREF_MODEL="deepseek-chat"
```

### 方式二：交互式配置（Windows）

```bash
setup.bat
```

按提示填写 API 信息，配置将保存到 `config/config.json`（已加入 `.gitignore`）。

### 使用本地 Ollama（免费，无需 API Key）

先确保 Ollama 已安装并运行，然后设置：

```bash
export CODEREF_PROVIDER="ollama"
export CODEREF_BASE_URL="http://localhost:11434/v1"
export CODEREF_MODEL="qwen2.5:7b"
export CODEREF_API_KEY="ollama"
```

### 支持的模型

| 提供商 | 推荐模型 | 说明 |
|--------|---------|------|
| DeepSeek | `deepseek-chat` | 性价比高，中文友好 |
| OpenAI | `gpt-4o` / `gpt-4o-mini` | 质量最高 |
| Ollama | `qwen2.5:7b` / `llama3.1:8b` | 免费，本地运行 |

---

## MCP 客户端配置

### Trae

**UI 配置（推荐）：**

1. 打开 Trae → 设置 → MCP Servers
2. 点击 "Add Custom MCP Server"
3. 填写：
   - **Name**: `coderef-ai`
   - **Command**: `python`
   - **Args**: `-m`, `core.mcp_server`
   - **Working Directory**: 指向 coderef-ai 的绝对路径
4. 保存后，Trae 会自动启动 MCP Server

**配置文件（`~/.trae-cn/mcp.json`）：**

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

### Claude Desktop

在 Claude Desktop 的配置文件中添加（位置因平台而异）：

**Windows:** `%APPDATA%\Claude\claude_desktop_config.json`  
**macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`

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

### Cursor

在 Cursor 的 MCP 配置中添加：

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

### 通用配置模板

所有 MCP 客户端配置本质相同，注意替换 `cwd` 为你的实际路径：

```json
{
  "mcpServers": {
    "coderef-ai": {
      "command": "python",
      "args": ["-m", "core.mcp_server"],
      "cwd": "/absolute/path/to/coderef-ai"
    }
  }
}
```

---

## 6 个 MCP 工具

| 工具 | 功能 | 模式 | 需要 LLM |
|------|------|------|---------|
| `coderef_audit` | 11 审计工具一键产出 + 自动降噪 + 知识图谱构建 | 后台 | 否 |
| `coderef_architecture` | 架构分析图谱 + 交互式 HTML 模块画布 | 同步 | 否 |
| `coderef_docs` | 项目 Wiki 文档生成 + 子项目探测 | 后台 | 是 |
| `coderef_query` | 知识图谱结构化查询（9 种查询类型） | 同步 | 否 |
| `coderef_whitelist` | 白名单管理 + 核心模块规则配置 | 同步 | 否 |
| `coderef_task_status` | 后台任务状态查询 | 同步 | 否 |

---

## 使用示例

配置完成后，在 AI 对话中直接描述需求即可，AI 会自动调用对应工具：

**"分析这个项目的代码质量"**  
→ AI 调用 `coderef_audit(project_path="/path/to/project", background=True)`

**"生成这个项目的文档"**  
→ AI 调用 `coderef_docs(project_path="/path/to/project", background=True)`

**"这个函数被谁调用？"**  
→ AI 调用 `coderef_query(project_path="/path/to/project", query_type="callers", func_name="login")`

**"修改 auth.py 会影响哪些模块？"**  
→ AI 调用 `coderef_query(project_path="/path/to/project", query_type="impact", file_path="auth.py")`

**"看看这个项目的架构"**  
→ AI 调用 `coderef_architecture(project_path="/path/to/project")`

---

## 知识图谱查询速查

知识图谱在运行 audit / architecture / docs 后自动构建，持久化到 `cache/kg/`。一次构建，跨会话复用。

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
| 查询某个节点的所有关系 | `relations` | `node_id="node_xxx"` |

**实体类型：** `module` / `function` / `class` / `method` / `config` / `constant`  
**关系类型：** `CONTAINS` / `IMPORTS` / `INHERITS` / `CALLS` / `REFERENCES`

---

## 白名单使用

审查审计报告后，将确认无误的误报加入白名单，下次审计时自动过滤：

```python
# 添加白名单条目
coderef_whitelist(project_path="/path/to/project", action="add", entries=[
    {"file": "utils.py", "rule": "不安全随机数"},
    {"category": "security"},
])

# 查看当前白名单
coderef_whitelist(project_path="/path/to/project", action="list")

# 清空白名单
coderef_whitelist(project_path="/path/to/project", action="clear")
```

白名单文件存储在 `cache/pipeline/{project_hash}/whitelist.json`。

---

## 核心模块规则配置

如果 Wiki 文档生成漏掉了某些核心模块，可以通过规则配置来修正：

```python
# 查看当前规则
coderef_whitelist(project_path="/path/to/project", action="core_rules_get")

# 自定义规则
coderef_whitelist(project_path="/path/to/project", action="core_rules_set", core_rules={
    "core_names": ["my_core_module", "shared"],                      # 强制核心模块名
    "entry_files": ["main.py", "app.py", "server.py", "cli.py"],     # 入口文件名
    "min_files": 5                                                    # 文件数阈值
})

# 恢复默认规则
coderef_whitelist(project_path="/path/to/project", action="core_rules_reset")
```

**默认规则：**
- `entry_files`: `["main.py", "app.py", "server.py", "run.py", "cli.py", "index.py", "start.py"]`
- `min_files`: 10
- `core_names`: 空

规则存储在 `cache/pipeline/core_rules_{project_hash}.json`。

---

## 故障排查

### MCP Server 启动失败

```bash
cd /path/to/coderef-ai
python -m core.mcp_server
# 观察输出，检查是否有依赖缺失或语法错误
```

常见原因：
- Python 版本低于 3.10
- `tree-sitter` 依赖未安装（`pip install -r requirements.txt`）
- 工作目录路径不正确

### 后台任务一直没有完成

```python
coderef_task_status(task_id="xxx")
# 返回 running → 还在执行，继续等待
# 返回 error → 查看错误信息
# 返回 completed → 已完成，报告已保存到 coderef-report/
```

### 知识图谱查询返回空

知识图谱需要先运行 audit / architecture / docs 才会构建。如果之前没有运行过：

```python
coderef_audit(project_path="/path/to/project", background=True)
```

### 中文路径支持

目前代码分析器对中文路径兼容性有限，建议项目路径使用纯英文。

### Wiki 文档生成失败

检查 LLM 配置是否正确：

```bash
# 验证 LLM 连接
python -c "
from core.llm_integration import get_llm_client
client = get_llm_client()
print(client.models.list())
"
```

---

## 架构说明

```
AI 编程助手 (Trae / Claude Desktop / Cursor)
   │
   └── coderef-ai MCP Server (v3.1, 6 个工具)
          │
          ├── coderef_audit ─── 11 检测器管线
          │      ├── 治理审计 (governance_audit)
          │      ├── Agent 安全 (agent_security_auditor)
          │      ├── 依赖扫描 (sca_checker)
          │      ├── 技术债务 (tech_debt_detector)
          │      ├── 完整性检查 (integrity_checker)
          │      ├── 盲区检测 (blind_spot_detector)
          │      ├── 创新传播 (innovation_propagation_detector)
          │      ├── 垃圾文件 (junk_detector)
          │      ├── 资源遗漏 (resource_gap_detector)
          │      ├── 代码精简 (code_simplifier)
          │      └── 项目成熟度 (project_maturity_checker)
          │      ├── 交叉验证（置信度分级 HIGH/MEDIUM/LOW）
          │      ├── 三级自动降噪（AutoNoiseFilter）
          │      └── 自动构建知识图谱（SQLite）
          │
          ├── coderef_architecture ─── 架构图谱
          │      └── 交互式 HTML 模块画布 (vis-network)
          │
          ├── coderef_docs ─── Wiki 文档
          │      ├── Stage 1: AST 全量元数据提取
          │      ├── Stage 2: LLM 逐模块归纳
          │      └── Stage 3: LLM 生成文档 + 编校验证
          │
          ├── coderef_query ─── 知识图谱
          │      └── SQLite 持久化，9 种查询类型
          │
          ├── coderef_whitelist ─── 白名单 + 核心规则
          └── coderef_task_status ─── 后台任务查询
```

### 关键设计决策

1. **单 Server 集中管控**：6 个工具统一暴露，无需为每个检测器单独配置 MCP Server
2. **审计无需 LLM**：11 个检测器均基于静态分析，离线可用，零 API 成本
3. **知识图谱持久化**：一次构建，跨会话复用，节省重复分析时间
4. **交叉验证反幻觉**：多工具独立分析同一项目，相互验证，解决 AI 自查幻觉
5. **后台任务模式**：长任务（audit / docs）异步执行，避免 MCP 超时
6. **项目隔离**：每个项目独立缓存，切换项目不互相干扰

---

## 安全与隐私

- **API 密钥**：存储在 `config/config.json` 或环境变量中，`config/` 和 `cache/` 目录已加入 `.gitignore`，不会提交到 Git
- **代码分析**：完全在本地运行，审计和知识图谱功能无需网络
- **开源前清理**：删除 `cache/` 和 `config/` 目录即可清除所有敏感数据

```bash
# 开源前清理
rm -rf cache/ config/
```