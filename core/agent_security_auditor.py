"""
Agent 安全审计器 —— 专为 AI Agent 系统设计的风险检测

检测维度（基于 OWASP Top 10 for LLM Applications + Agent 安全实践）：

1. 提示注入风险 (Prompt Injection)
   - 检测用户输入直接拼接到 prompt 中
   - 检测未做输入过滤的 f-string/format 拼接

2. 上下文操纵风险 (Context Manipulation)
   - 检测外部文档/URL 内容直接注入到上下文
   - 检测未分类/未过滤的外部数据源

3. 工具滥用风险 (Tool Misuse)
   - 检测 Agent 可调用的危险函数（文件删除、命令执行、数据库写入）
   - 检测缺失权限检查的工具调用

4. 预算/资源耗尽风险 (Budget Exhaustion)
   - 检测无限制的 LLM 调用循环
   - 检测缺失 token 预算控制的流程

5. 数据泄露风险 (Data Exfiltration)
   - 检测敏感数据通过 LLM 输出到外部 API
   - 检测日志中记录了完整 prompt 内容

5.5 PII 泄露风险 (PII Leak)
   - 检测日志中打印邮箱、手机号、身份证号等个人身份信息
   - 检测 PII 明文拼接到 f-string 中

5.6 安全配置风险 (Security Config)
   - 检测 DEBUG=True 的生产环境配置
   - 检测不安全反序列化（pickle/yaml.load）
   - 检测 CORS 配置过于宽松
   - 检测网络请求缺少超时设置

6. 自主行为风险 (Autonomous Action)
   - 检测 Agent 未经人类确认即可执行危险操作
   - 检测缺失 human-in-the-loop 的关键路径

7. 知识投毒风险 (Knowledge Poisoning)
   - 检测 RAG 检索结果未做可信度校验
   - 检测向量数据库写入未做权限控制

作者: CodeRef Team
版本: v1.0
"""

import os
import re
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict


@dataclass
class AgentSecurityRisk:
    """Agent 安全风险"""
    risk_id: str
    risk_name: str
    category: str  # prompt_injection / context_manipulation / tool_misuse / budget / data_exfil / autonomous / knowledge
    severity: str  # blocker / critical / high / medium / low
    file_path: str
    line_number: int
    line_content: str
    detail: str
    suggestion: str
    cwe_id: str = ""  # 映射到传统 CWE（如果适用）


SEVERITY_ORDER = {"blocker": 0, "critical": 1, "high": 2, "medium": 3, "low": 4}


class AgentSecurityAuditor:
    """Agent 安全审计器"""

    # ─── 提示注入检测 ───
    PROMPT_INJECTION_PATTERNS = [
        # 直接拼接用户输入到提示词
        (re.compile(r'f["\'].*\{.*(?:user_input|user_message|query|question|prompt|input|content).*\}', re.IGNORECASE),
         "AGENT-SEC-01", "提示注入风险", "critical",
         "检测到用户输入直接拼接到 prompt 中，攻击者可通过精心构造的输入绕过 Agent 的安全限制",
         "使用结构化 prompt 模板 + 参数注入，或对用户输入做分层标记（system/user/assistant）"),
        # 未过滤的用户输入进入 system prompt
        (re.compile(r'(?:system_prompt|sys_prompt|system_message)\s*[+=]\s*.*\{.*\}', re.IGNORECASE),
         "AGENT-SEC-01", "提示注入风险", "critical",
         "检测到 system prompt 中包含用户可控变量，这是最高风险的注入点",
         "system prompt 应完全由开发者控制，不包含任何用户输入"),
        # 多轮对话中未区分角色
        (re.compile(r'messages\.append\s*\(\s*\{.*role.*user.*content.*\}', re.IGNORECASE),
         "AGENT-SEC-02", "角色混淆风险", "high",
         "检测到消息列表构建时用户内容可能与系统指令混淆",
         "确保 messages 列表中 role 字段正确，且 system 角色的消息在任何用户消息之前"),
    ]

    # ─── 上下文操纵检测 ───
    CONTEXT_MANIPULATION_PATTERNS = [
        # 外部 URL 内容直接注入上下文
        (re.compile(r'(?:requests\.get|urllib|fetch|httpx\.get)\s*\(.*\).*\.text.*prompt', re.IGNORECASE),
         "AGENT-SEC-03", "外部内容注入", "high",
         "检测到外部 URL 内容直接注入到 LLM 上下文，攻击者可通过控制URL内容操控Agent",
         "对外部内容做沙箱化处理：限制长度、过滤控制字符、添加来源标记"),
        # 未做内容过滤的 RAG 检索
        (re.compile(r'(?:retrieve|search|query).*\.content.*prompt', re.IGNORECASE),
         "AGENT-SEC-04", "知识投毒风险", "medium",
         "检测到 RAG 检索结果直接注入到 prompt，未经可信度校验",
         "对检索结果做可信度评分，过滤低质量内容，添加来源引用"),
        # 未限制长度的上下文
        (re.compile(r'context\s*\+=\s*|context\.append|context\.extend', re.IGNORECASE),
         "AGENT-SEC-05", "上下文溢出风险", "medium",
         "检测到上下文无限追加，可能导致 token 超限或上下文窗口溢出",
         "实现上下文窗口管理：滑动窗口、摘要压缩、或限制最大 token 数"),
    ]

    # ─── 工具滥用检测 ───
    TOOL_MISUSE_PATTERNS = [
        # 文件删除/修改
        (re.compile(r'(?:os\.remove|os\.unlink|shutil\.rmtree|Path\.unlink|os\.rename)', re.IGNORECASE),
         "AGENT-SEC-06", "危险文件操作", "blocker",
         "检测到 Agent 可执行文件删除/重命名操作，可能被滥用导致数据丢失",
         "添加 human-in-the-loop 确认、文件操作白名单、或沙箱化执行环境"),
        # 命令执行
        (re.compile(r'(?:subprocess|os\.system|os\.popen|os\.exec|eval|exec)\s*\(', re.IGNORECASE),
         "AGENT-SEC-07", "危险命令执行", "blocker",
         "检测到 Agent 可执行系统命令，这是最高风险的操作",
         "禁用命令执行能力，或严格限制为白名单命令 + 沙箱环境"),
        # 数据库写入
        (re.compile(r'(?:\.execute\s*\(|\.commit\s*\(|\.write\s*\(|\.save\s*\()', re.IGNORECASE),
         "AGENT-SEC-08", "无确认写入操作", "high",
         "检测到 Agent 可执行数据库写入/文件保存操作，未经人工确认",
         "添加写入前确认机制，或实现 dry-run 模式先预览变更"),
        # 网络请求（可能被 SSRF 利用）
        (re.compile(r'(?:requests\.(?:get|post|put|delete)|httpx\.(?:get|post)|urllib\.request)', re.IGNORECASE),
         "AGENT-SEC-09", "不受控网络请求", "medium",
         "检测到 Agent 可发起网络请求，可能被用于 SSRF 或数据外传",
         "限制网络请求的目标域名白名单，或使用代理层过滤"),
    ]

    # ─── 预算/资源耗尽检测 ───
    BUDGET_EXHAUSTION_PATTERNS = [
        # 无限制 LLM 循环
        (re.compile(r'while\s+(?:True|1)\s*:.*(?:chat|completion|generate|invoke|call)', re.IGNORECASE),
         "AGENT-SEC-10", "无限LLM调用循环", "blocker",
         "检测到无限循环中调用 LLM，可能导致 API 费用失控",
         "添加 max_iterations 限制、token 预算计数器、或费用上限"),
        # 缺失 token 预算
        (re.compile(r'(?:max_tokens|max_length)\s*=\s*(?:None|0|99999)', re.IGNORECASE),
         "AGENT-SEC-11", "Token预算未设置", "high",
         "检测到 LLM 调用未设置合理的 max_tokens 限制",
         "设置合理的 max_tokens（如 4096），防止单次调用消耗过多资源"),
        # 循环中累积上下文
        (re.compile(r'for\s+\w+\s+in\s+.*:\s*.*(?:messages|context|prompt).*append', re.IGNORECASE),
         "AGENT-SEC-12", "上下文无限累积", "medium",
         "检测到循环中无限追加消息到上下文，可能导致 token 消耗指数增长",
         "实现上下文窗口管理：仅保留最近 N 轮对话，或使用摘要压缩"),
    ]

    # ─── 数据泄露检测 ───
    DATA_EXFIL_PATTERNS = [
        # 日志中记录完整 prompt
        (re.compile(r'(?:logger\.(?:info|debug|error|warning)|print|logging)\s*\(.*(?:prompt|messages|system_prompt)', re.IGNORECASE),
         "AGENT-SEC-13", "Prompt日志泄露", "high",
         "检测到日志中可能记录了完整 prompt 内容，敏感信息可能被泄露",
         "对日志中的 prompt 内容做脱敏处理，或使用专门的审计日志"),
        # API Key 在请求中传递
        (re.compile(r'headers\s*\[.*(?:api.?key|authorization|token).*\]', re.IGNORECASE),
         "AGENT-SEC-14", "API Key 明文传递", "medium",
         "检测到 API Key 在 HTTP 请求头中明文传递",
         "使用环境变量存储 API Key，通过密钥管理服务注入"),
        # 敏感数据输出到外部
        (re.compile(r'(?:requests\.(?:post|put)|httpx\.(?:post|put)).*response.*text', re.IGNORECASE),
         "AGENT-SEC-15", "敏感数据外传风险", "medium",
         "检测到 LLM 响应内容通过网络请求发送到外部",
         "审计所有外部网络请求的目的地，添加数据外传检测"),
    ]

    # ─── PII 泄露检测 ───
    PII_LEAK_PATTERNS = [
        # 日志中打印邮箱
        (re.compile(r'(?:logger\.(?:info|debug|error|warning)|print|logging)\s*\(.*@.*\.', re.IGNORECASE),
         "AGENT-SEC-18", "PII日志泄露（邮箱）", "high",
         "检测到日志中可能包含邮箱地址，违反 GDPR/CCPA 数据隐私法规",
         "对日志中的 PII 做脱敏处理：user@example.com → u***@example.com"),
        # 日志中打印手机号
        (re.compile(r'(?:logger\.(?:info|debug|error|warning)|print|logging)\s*\(.*(?:\+?86)?\s*1[3-9]\d{9}', re.IGNORECASE),
         "AGENT-SEC-19", "PII日志泄露（手机号）", "high",
         "检测到日志中可能包含手机号码，违反数据隐私法规",
         "对日志中的手机号做脱敏：139****1234，或完全移除"),
        # 日志中打印身份证号
        (re.compile(r'(?:logger\.(?:info|debug|error|warning)|print|logging)\s*\(.*\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]', re.IGNORECASE),
         "AGENT-SEC-20", "PII日志泄露（身份证号）", "blocker",
         "检测到日志中可能包含身份证号码，严重违反数据隐私法规",
         "身份证号绝对不应出现在日志中，立即移除相关日志语句"),
        # f-string 中直接拼接用户数据
        (re.compile(r'f["\'].*\{.*(?:email|phone|mobile|id_card|passport|ssn|address|birthday).*\}', re.IGNORECASE),
         "AGENT-SEC-21", "PII明文拼接", "high",
         "检测到用户敏感信息直接拼接到字符串中，可能泄露到日志或响应",
         "使用脱敏函数处理后再输出，或使用结构化日志格式"),
    ]

    # ─── 安全配置检查 ───
    SECURITY_CONFIG_PATTERNS = [
        # 调试模式未关闭
        (re.compile(r'(?:debug|DEBUG)\s*=\s*True', re.IGNORECASE),
         "AGENT-SEC-22", "调试模式开启", "high",
         "检测到 DEBUG=True，生产环境应关闭调试模式",
         "生产环境设置 DEBUG=False，或通过环境变量控制"),
        # 不安全的反序列化
        (re.compile(r'(?:pickle\.loads|yaml\.load\s*\(|json\.loads\s*\(.*ensure_ascii)', re.IGNORECASE),
         "AGENT-SEC-23", "不安全反序列化", "blocker",
         "检测到使用 pickle.loads 或 yaml.load（非 SafeLoader），可被利用执行任意代码",
         "使用 yaml.safe_load() 替代 yaml.load()，避免 pickle 反序列化不可信数据"),
        # CORS 配置过于宽松
        (re.compile(r'allow_origins\s*=\s*\[.*\*.*\]|Access-Control-Allow-Origin.*\*', re.IGNORECASE),
         "AGENT-SEC-24", "CORS配置过宽", "high",
         "检测到 CORS 配置允许所有来源（*），可能被恶意站点利用",
         "将 allow_origins 限制为具体域名白名单"),
        # 超时未设置
        (re.compile(r'(?:requests\.(?:get|post|put|delete)|httpx\.(?:get|post))\s*\([^)]*\)', re.IGNORECASE),
         "AGENT-SEC-25", "网络请求无超时", "medium",
         "检测到网络请求未设置 timeout 参数，可能导致请求永久挂起",
         "所有网络请求添加 timeout=30 参数"),
        # 缺少速率限制
        (re.compile(r'(?:def\s+\w+|async\s+def\s+\w+)\s*\(.*\).*:\s*\n\s*(?:result|response|data)\s*=.*(?:generate|completion|chat)', re.IGNORECASE),
         "AGENT-SEC-26", "LLM调用缺少限流", "medium",
         "检测到 LLM 调用未做速率限制，可能被滥用导致 API 费用暴涨",
         "添加 rate limiter（如 token bucket），限制每分钟调用次数"),
    ]

    # ─── 自主行为检测 ───
    AUTONOMOUS_ACTION_PATTERNS = [
        # 自动重试逻辑（else 分支中有 retry/redo/recreate）
        (re.compile(r'else\s*:.*(?:retry|redo|recreate)', re.IGNORECASE),
         "AGENT-SEC-16", "无确认自动重试", "medium",
         "检测到 Agent 在操作失败后自动重试，未征求人类确认",
         "添加失败后人工确认环节，或限制重试次数"),
        # 基于结果的自动判断（低风险，常见模式）
        (re.compile(r'if\s+(?:not\s+)?(?:result|success|ok)\s*:', re.IGNORECASE),
         "AGENT-SEC-16", "无确认自动重试", "low",
         "检测到基于结果的条件判断，需人工确认是否为自动重试逻辑",
         "如果是自动重试，添加人工确认环节；如果是正常流程控制，可忽略"),
        # 自动修改自身配置（仅匹配 self.config/self.settings/self.params 赋值，不匹配通用 self.xxx = result.xxx）
        (re.compile(r'(?:self\.(?:config|settings|params)\s*(?:\[|\.update|\.set))', re.IGNORECASE),
         "AGENT-SEC-17", "自修改配置风险", "high",
         "检测到 Agent 可能修改自身配置或参数，行为不可预测",
         "配置应设为只读，或添加配置变更审计日志"),
        # 缺少 human-in-the-loop
        # 通过检测是否有 confirm/approve 相关函数来实现
    ]

    # 排除模式（工具定义中的注释/文档字符串）
    EXCLUDE_PATTERNS = [
        re.compile(r'^\s*#', re.IGNORECASE),
        re.compile(r'^\s*"""', re.IGNORECASE),
        re.compile(r'^\s*//', re.IGNORECASE),
    ]

    # ─── 防御层级韧性检测（检查"缺失"的防御模式，而非"存在"的风险） ───
    RESILIENCE_GAP_CHECKS = [
        # 重试退避 —— 检测 tenacity / @retry / exponential backoff
        {
            "id": "AGENT-RESILIENCE-01",
            "name": "缺少重试退避",
            "severity": "high",
            "detail": "未检测到 tenacity/@retry/指数退避等重试机制，LLM API 调用遇到暂时性故障（429/503/超时）会直接失败",
            "suggestion": "使用 tenacity 库添加重试：@retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=1, max=10))",
            "patterns": [
                re.compile(r'tenacity|from\s+tenacity', re.IGNORECASE),
                re.compile(r'@retry\b', re.IGNORECASE),
                re.compile(r'stop_after_attempt|wait_exponential|retry_if_exception', re.IGNORECASE),
            ],
        },
        # 异常过滤 —— 区分"该重试"和"不该重试"的异常
        {
            "id": "AGENT-RESILIENCE-02",
            "name": "缺少异常分类过滤",
            "severity": "medium",
            "detail": "未检测到 retry_if_exception_type 或按异常类型分类处理，遇到不可重试错误（如 401 认证失败）也会重试，浪费资源",
            "suggestion": "使用 retry_if_exception_type((RateLimitError, APITimeoutError, APIError)) 区分可重试和不可重试异常",
            "patterns": [
                re.compile(r'retry_if_exception_type', re.IGNORECASE),
                re.compile(r'except\s+\(.*Timeout.*Error.*\).*retry', re.IGNORECASE),
            ],
        },
        # 模型回退 —— 主模型挂了有备胎
        {
            "id": "AGENT-RESILIENCE-03",
            "name": "缺少模型回退",
            "severity": "high",
            "detail": "未检测到 LLM 模型注册表或回退机制，主模型不可用时服务完全中断",
            "suggestion": "实现 LLMRegistry 注册表 + 环形索引轮换：try 主模型 → except 切备胎 → 确保总有一个可用",
            "patterns": [
                re.compile(r'(?:LLMRegistry|ModelRegistry|llm_registry|fallback.*llm|backup.*model)', re.IGNORECASE),
                re.compile(r'try:.*(?:chat|completion|generate).*except.*(?:chat|completion|generate)', re.IGNORECASE),
                re.compile(r'next_index\s*=\s*\(.*\+\s*1\)\s*%\s*len', re.IGNORECASE),
            ],
        },
        # 上下文截断 —— 防止 token 炸了
        {
            "id": "AGENT-RESILIENCE-04",
            "name": "缺少上下文截断",
            "severity": "high",
            "detail": "未检测到 trim_messages 或上下文窗口管理，多轮对话中 token 可能无限增长导致 API 错误或费用暴涨",
            "suggestion": "实现上下文截断：trim_messages(strategy=\"last\", max_tokens=2000) 或滑动窗口 + 摘要压缩",
            "patterns": [
                re.compile(r'trim_messages|trim_context|context_window|max_context', re.IGNORECASE),
                re.compile(r'max_tokens\s*=\s*\d{3,4}', re.IGNORECASE),
                re.compile(r'(?:messages|context)\s*=\s*(?:messages|context)\s*\[-?\d+:\]', re.IGNORECASE),
            ],
        },
        # 异步记忆 —— 存记忆不阻塞响应
        {
            "id": "AGENT-RESILIENCE-05",
            "name": "缺少异步记忆存储",
            "severity": "medium",
            "detail": "未检测到 asyncio.create_task 或异步记忆存储，保存记忆时可能阻塞主流程响应",
            "suggestion": "使用 asyncio.create_task(memory.add(...)) 异步存储记忆，避免阻塞 LLM 响应",
            "patterns": [
                re.compile(r'asyncio\.create_task|create_task\(', re.IGNORECASE),
                re.compile(r'memory\.(?:add|save|store)', re.IGNORECASE),
            ],
        },
        # 流式响应 —— 用户不用干等
        {
            "id": "AGENT-RESILIENCE-06",
            "name": "缺少流式响应",
            "severity": "low",
            "detail": "未检测到 StreamingResponse/SSE/stream=True，用户可能长时间等待完整响应",
            "suggestion": "使用 StreamingResponse 或 stream=True 参数实现流式输出，改善用户体验",
            "patterns": [
                re.compile(r'StreamingResponse|stream\s*=\s*True|text/event-stream|ServerSentEvent', re.IGNORECASE),
                re.compile(r'streaming\s*=|stream\s*:\s*True|yield\s+.*chunk', re.IGNORECASE),
            ],
        },
        # 连接池 —— 防止连接断了不知道
        {
            "id": "AGENT-RESILIENCE-07",
            "name": "缺少连接池探活",
            "severity": "medium",
            "detail": "未检测到 pool_pre_ping/pool_recycle 等连接池配置，数据库连接断开后可能长时间不可用",
            "suggestion": "配置连接池：pool_pre_ping=True, pool_recycle=1800，确保连接断开后自动重建",
            "patterns": [
                re.compile(r'pool_pre_ping|pool_recycle|create_engine.*pool', re.IGNORECASE),
            ],
        },
        # 状态持久化 —— 服务器重启不丢状态
        {
            "id": "AGENT-RESILIENCE-08",
            "name": "缺少状态持久化",
            "severity": "medium",
            "detail": "未检测到 checkpoint/saver 等状态持久化机制，服务器重启后对话状态丢失",
            "suggestion": "使用 checkpoint（如 AsyncPostgresSaver）定期保存状态，确保重启后可恢复",
            "patterns": [
                re.compile(r'checkpoint|Saver|saver|state\.persist|save_state|load_state', re.IGNORECASE),
                re.compile(r'AsyncPostgresSaver|SqliteSaver|MemorySaver', re.IGNORECASE),
            ],
        },
        # 可观测性 —— 出问题能定位
        {
            "id": "AGENT-RESILIENCE-09",
            "name": "缺少可观测性",
            "severity": "medium",
            "detail": "未检测到 Prometheus metrics / Counter/Histogram 等可观测性指标，出问题时难以定位根因",
            "suggestion": "添加 Prometheus metrics：Counter 统计调用次数，Histogram 统计延迟，Labels 区分模型/状态",
            "patterns": [
                re.compile(r'Counter|Histogram|Gauge|prometheus_client|prometheus', re.IGNORECASE),
                re.compile(r'metrics\s*=|\.observe\(|\.inc\(|\.set\(', re.IGNORECASE),
            ],
        },
        # 日志上下文 —— 日志带用户 ID 方便排查
        {
            "id": "AGENT-RESILIENCE-10",
            "name": "缺少日志上下文",
            "severity": "low",
            "detail": "未检测到 bind_context/structured logging 等日志上下文绑定，排查问题时无法关联用户请求",
            "suggestion": "使用 bind_context(subject_id=subject) 或 structlog 绑定请求上下文，日志自动带用户 ID",
            "patterns": [
                re.compile(r'bind_context|structlog|extra\s*=\s*\{.*(?:user_id|subject_id|request_id)', re.IGNORECASE),
                re.compile(r'logger\.bind\(|logging\.LoggerAdapter', re.IGNORECASE),
            ],
        },
    ]

    def __init__(self):
        pass

    def audit(self, project_path: str) -> List[AgentSecurityRisk]:
        """执行 Agent 安全审计"""
        risks = []

        # 加载项目专属的 cache 硬编码优化（白名单）
        from core.shared_filter import SharedFilter
        SharedFilter.load_cache(project_path)

        # 收集所有 Python 文件
        # 只排除当前目录名，不影响路径中包含该词的项目
        exclude_dirs = {
            "__pycache__", "node_modules", ".git", "venv", ".venv", "env",
            "Lib", "lib", "lib64", "site-packages", "dist-packages",
            "third_party", ".gitnexus", "data", "docs", "reports",
            "cache", "coderef-report", "logs", "build", "dist",
        }
        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in exclude_dirs]
            for f in files:
                if not f.endswith(".py"):
                    continue
                fpath = os.path.join(root, f)
                file_risks = self._scan_file(fpath)
                risks.extend(file_risks)

        # 项目级防御层级韧性缺口检测（检查缺失的防御模式）
        resilience_gaps = self._check_resilience_gaps(project_path)
        risks.extend(resilience_gaps)

        # 过滤 cache 白名单（用户标记为可接受的安全风险）
        risks = [
            r for r in risks
            if not SharedFilter.is_security_whitelisted(r.risk_id, r.file_path, r.line_number)
        ]

        # 按严重程度排序
        risks.sort(key=lambda r: (SEVERITY_ORDER.get(r.severity, 99), r.file_path, r.line_number))
        return risks

    def _scan_file(self, filepath: str) -> List[AgentSecurityRisk]:
        """扫描单个文件"""
        risks = []
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except (OSError, IOError):
            return risks

        in_docstring = False
        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped:
                continue

            # 跟踪多行 docstring
            if stripped.startswith('"""') or stripped.startswith("'''"):
                in_docstring = not in_docstring
                continue
            if in_docstring:
                continue

            # 跳过注释
            if any(p.match(stripped) for p in self.EXCLUDE_PATTERNS):
                continue

            # 判断是否为 logger 行（PII 检测需要 logger 行，其他检测跳过）
            is_logger = bool(re.match(r'logger\.', stripped))
            # 判断是否为报告生成代码（lines.append 构建 Markdown 报告，不是真正的注入）
            is_report_gen = bool(re.match(r'lines\.append\(', stripped))

            # 检测所有维度
            for patterns, category_key in [
                (self.PROMPT_INJECTION_PATTERNS, "prompt_injection"),
                (self.CONTEXT_MANIPULATION_PATTERNS, "context_manipulation"),
                (self.TOOL_MISUSE_PATTERNS, "tool_misuse"),
                (self.BUDGET_EXHAUSTION_PATTERNS, "budget"),
                (self.DATA_EXFIL_PATTERNS, "data_exfil"),
                (self.PII_LEAK_PATTERNS, "pii_leak"),
                (self.SECURITY_CONFIG_PATTERNS, "security_config"),
                (self.AUTONOMOUS_ACTION_PATTERNS, "autonomous"),
            ]:
                # PII 检测需要检查 logger 行，其他检测跳过 logger 行
                if category_key != "pii_leak" and is_logger:
                    continue
                # 跳过报告生成代码（lines.append 构建 Markdown 报告）
                if is_report_gen:
                    continue
                for pattern, risk_id, risk_name, severity, detail, suggestion in patterns:
                    if pattern.search(stripped):
                        # 跳过模式定义自身（如类中的正则表达式定义）
                        if self._is_pattern_definition(stripped, risk_name):
                            continue
                        risks.append(AgentSecurityRisk(
                            risk_id=risk_id,
                            risk_name=risk_name,
                            category=category_key,
                            severity=severity,
                            file_path=filepath,
                            line_number=i,
                            line_content=stripped[:150],
                            detail=detail,
                            suggestion=suggestion,
                        ))

        return risks

    def _check_resilience_gaps(self, project_path: str) -> List[AgentSecurityRisk]:
        """检查防御层级韧性缺口 —— 检测缺失的防御模式
        
        与逐行扫描不同，这是项目级检查：扫描所有 .py 文件，判断每种防御模式是否存在。
        如果某种防御模式在整个项目中都没有找到，则生成一个缺口风险。
        """
        risks = []
        
        # 收集所有 Python 文件内容
        exclude_dirs = {
            "__pycache__", "node_modules", ".git", "venv", ".venv", "env",
            "Lib", "lib", "lib64", "site-packages", "dist-packages",
            "third_party", ".gitnexus", "data", "docs", "reports",
            "cache", "coderef-report", "logs", "build", "dist",
        }
        all_content = ""
        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in exclude_dirs]
            for f in files:
                if not f.endswith(".py"):
                    continue
                try:
                    with open(os.path.join(root, f), "r", encoding="utf-8", errors="ignore") as fh:
                        all_content += fh.read() + "\n"
                except (OSError, IOError):
                    continue
        
        if not all_content.strip():
            return risks
        
        # 对每种防御模式，检查是否在项目中存在
        for check in self.RESILIENCE_GAP_CHECKS:
            found = False
            for pattern in check["patterns"]:
                if pattern.search(all_content):
                    found = True
                    break
            
            if not found:
                # 该防御模式缺失，生成缺口风险
                risks.append(AgentSecurityRisk(
                    risk_id=check["id"],
                    risk_name=check["name"],
                    category="resilience_gap",
                    severity=check["severity"],
                    file_path="",  # 项目级检查，无具体文件
                    line_number=0,
                    line_content="",
                    detail=check["detail"],
                    suggestion=check["suggestion"],
                ))
        
        return risks

    def _is_pattern_definition(self, line: str, risk_name: str) -> bool:
        """检查是否匹配了工具自身的检测模式定义"""
        # 匹配 AGENT-SEC- 编号
        if re.search(r'AGENT-SEC-\d+', line, re.IGNORECASE):
            return True
        # 匹配规则描述字符串（如 "检测到 DEBUG=True" 或 "检测到使用 pickle"）
        if re.search(r'["\']检测到', line):
            return True
        # 匹配规则建议字符串（如 "使用 yaml.safe_load() 替代"）
        if re.search(r'["\']使用\s.*(?:替代|替换|避免)', line):
            return True
        # 匹配安全规则的正则表达式定义行（如 re.compile(r'...')）
        if re.search(r're\.compile\(', line):
            return True
        # 匹配 CWE 映射行
        if re.search(r'CWE-\d+', line):
            return True
        return False

    def to_report(self, risks: List[AgentSecurityRisk], project_path: str) -> str:
        """生成 Agent 安全审计报告"""
        # 统计
        by_category = defaultdict(list)
        for r in risks:
            by_category[r.category].append(r)

        blocker = sum(1 for r in risks if r.severity == "blocker")
        critical = sum(1 for r in risks if r.severity == "critical")
        high = sum(1 for r in risks if r.severity == "high")
        medium = sum(1 for r in risks if r.severity == "medium")
        low = sum(1 for r in risks if r.severity == "low")

        # 评分
        penalty = blocker * 30 + critical * 20 + high * 10 + medium * 3 + low * 1
        score = max(0, min(100, 100 - penalty))
        grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"

        category_names = {
            "prompt_injection": "提示注入",
            "context_manipulation": "上下文操纵",
            "tool_misuse": "工具滥用",
            "budget": "预算/资源耗尽",
            "data_exfil": "数据泄露",
            "pii_leak": "PII泄露",
            "security_config": "安全配置",
            "autonomous": "自主行为",
            "knowledge": "知识投毒",
            "resilience_gap": "防御层级韧性缺口",
        }

        lines = [
            "# Agent 系统安全审计",
            "",
            f"> 项目: `{project_path}`",
            f"> 检测到 {len(risks)} 个 Agent 安全风险",
            "",
            "## 安全评分",
            "",
            f"| 评分 | 等级 | 阻断 | 严重 | 高危 | 中危 | 低危 |",
            f"|------|------|------|------|------|------|------|",
            f"| {score:.0f}/100 | **{grade}** | {blocker} | {critical} | {high} | {medium} | {low} |",
            "",
        ]

        if not risks:
            lines.append("✅ 未发现 Agent 安全风险。")
            return "\n".join(lines)

        # 按类别汇总
        lines.append("## 风险类别汇总")
        lines.append("")
        lines.append("| 类别 | 风险数 | 最高严重性 | 说明 |")
        lines.append("|------|--------|------------|------|")

        cat_details = {
            "prompt_injection": "用户输入可能被注入到 LLM prompt 中，绕过安全限制",
            "context_manipulation": "外部内容可能操控 Agent 的上下文和决策",
            "tool_misuse": "Agent 可能滥用工具能力执行危险操作",
            "budget": "Agent 可能消耗过多资源（API费用、Token）",
            "data_exfil": "敏感数据可能通过 Agent 泄露到外部",
            "pii_leak": "个人身份信息（PII）可能泄露到日志或响应中",
            "security_config": "安全配置不当可能导致生产环境风险",
            "autonomous": "Agent 可能未经确认执行自主行为",
            "knowledge": "知识库/向量数据库可能被投毒",
            "resilience_gap": "缺失的防御层级，如重试退避、模型回退、可观测性等",
        }

        for cat_key in ["prompt_injection", "tool_misuse", "budget", "data_exfil", "pii_leak", "security_config", "context_manipulation", "autonomous", "resilience_gap"]:
            cat_risks = by_category.get(cat_key, [])
            if not cat_risks:
                continue
            max_sev = min(cat_risks, key=lambda r: SEVERITY_ORDER.get(r.severity, 99)).severity
            sev_icon = "🔴" if max_sev in ("blocker", "critical") else "🟠" if max_sev == "high" else "🟡" if max_sev == "medium" else "⚪"
            lines.append(f"| {category_names.get(cat_key, cat_key)} | {len(cat_risks)} | {sev_icon} {max_sev} | {cat_details.get(cat_key, '')} |")

        lines.append("")

        # 详细风险列表
        lines.append("## 详细风险列表")
        lines.append("")

        for cat_key in ["prompt_injection", "tool_misuse", "budget", "data_exfil", "pii_leak", "security_config", "context_manipulation", "autonomous", "resilience_gap"]:
            cat_risks = by_category.get(cat_key, [])
            if not cat_risks:
                continue
            lines.append(f"### {category_names.get(cat_key, cat_key)}")
            lines.append("")
            lines.append("| ID | 严重性 | 文件 | 行号 | 描述 | 建议 |")
            lines.append("|----|--------|------|------|------|------|")
            for r in cat_risks[:20]:
                sev_icon = "🔴" if r.severity in ("blocker", "critical") else "🟠" if r.severity == "high" else "🟡" if r.severity == "medium" else "⚪"
                if r.file_path:
                    fname = os.path.basename(r.file_path)
                    file_col = f"`{fname}`"
                    line_col = str(r.line_number)
                else:
                    file_col = "项目全局"
                    line_col = "-"
                lines.append(
                    f"| {r.risk_id} | {sev_icon} {r.severity} | {file_col} | {line_col} | "
                    f"{r.risk_name}: {r.detail[:80]} | {r.suggestion[:80]} |"
                )
            if len(cat_risks) > 20:
                lines.append(f"| ... | ... | ... | ... | （还有 {len(cat_risks) - 20} 条） | ... |")
            lines.append("")

        lines.append("---")
        lines.append("")
        lines.append("### 关于 Agent 安全审计")
        lines.append("")
        lines.append("本报告基于 OWASP Top 10 for LLM Applications 和 Agent 安全最佳实践设计。")
        lines.append("传统 SAST 工具（如 SonarQube、Snyk）主要关注代码注入和依赖漏洞，")
        lines.append("但 AI Agent 系统引入了全新的攻击面：提示注入、上下文操纵、工具滥用、自主行为等。")
        lines.append("")
        lines.append("这些风险在传统安全扫描中完全不可见，需要专门的 Agent 安全审计。")
        lines.append("")
        lines.append("*扫描由 CodeRef Agent Security Auditor 执行*\n")
        lines.append("")
        lines.append("> **LLM 复查提示**：此报告可能包含误报。审查每条结果后，调用 `coderef_cache_whitelist` 工具将误报自动加入白名单，然后重新扫描。")

        return "\n".join(lines)


def audit_agent_security(project_path: str) -> str:
    """便捷函数"""
    auditor = AgentSecurityAuditor()
    risks = auditor.audit(project_path)
    return auditor.to_report(risks, project_path)