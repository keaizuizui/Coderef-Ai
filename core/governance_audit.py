# -*- coding: utf-8 -*-
"""
代码治理审计 —— 基于 AI 编程治理框架，检测铁律违反和错题本模式

检测维度：
1. 架构铁律：模块依赖方向、循环依赖、层级穿透
2. 变更铁律：高危操作模式识别
3. 质量铁律：函数长度、参数数量、嵌套深度、圈复杂度
4. 安全铁律：硬编码密钥、SQL注入风险、命令注入风险
5. 错题本模式：空catch块、裸except、不安全的默认值、竞态条件

与 CodeSimplifier 互补：
- CodeSimplifier 聚焦代码精简（YAGNI、死代码、过度工程）
- GovernanceAuditor 聚焦安全与架构合规（铁律、错题本）

作者: PersuadeAI Team
版本: v1.0
"""

import os
import re
import json
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
from dataclasses import dataclass, field

from loguru import logger
from core.shared_filter import SharedFilter

# 创建共享过滤器实例
_sf = SharedFilter()


# ═══════════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════════

SEVERITY_ORDER = {"blocker": 0, "critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}

# CWE 映射表：将 IRON 规则映射到 CWE 编号
CWE_MAPPING = {
    "IRON-SEC-01": "CWE-798",   # 硬编码凭据
    "IRON-SEC-02": "CWE-89",    # SQL注入
    "IRON-SEC-03": "CWE-78",    # 命令注入
    "IRON-SEC-04": "CWE-502",   # 不安全反序列化
    "IRON-SEC-05": "CWE-547",   # 硬编码地址
    "IRON-SEC-06": "CWE-95",    # 危险函数调用
    "IRON-SEC-07": "CWE-78",    # 不安全子进程
    "IRON-SEC-08": "CWE-22",    # 路径遍历
    "IRON-SEC-09": "CWE-532",   # 敏感信息泄露
    "IRON-SEC-10": "CWE-326",   # 弱加密算法
    "IRON-SEC-11": "CWE-918",   # SSRF
    "IRON-SEC-12": "CWE-79",    # XSS
    "IRON-SEC-13": "CWE-330",   # 不安全随机数
    "IRON-SEC-14": "CWE-327",   # 弱哈希算法
    "IRON-SEC-15": "CWE-295",   # 证书验证禁用
    "IRON-SEC-16": "CWE-400",   # 资源耗尽
}

# OWASP Top 10 2021 映射
OWASP_MAPPING = {
    "IRON-SEC-01": "A07:2021",  # 身份识别和认证失败
    "IRON-SEC-02": "A03:2021",  # 注入
    "IRON-SEC-03": "A03:2021",  # 注入
    "IRON-SEC-04": "A08:2021",  # 软件和数据完整性故障
    "IRON-SEC-06": "A03:2021",  # 注入
    "IRON-SEC-07": "A03:2021",  # 注入
    "IRON-SEC-08": "A01:2021",  # 访问控制失效
    "IRON-SEC-09": "A09:2021",  # 安全日志和监控故障
    "IRON-SEC-10": "A02:2021",  # 加密失败
    "IRON-SEC-11": "A10:2021",  # SSRF
    "IRON-SEC-12": "A03:2021",  # 注入
    "IRON-SEC-13": "A02:2021",  # 加密失败
    "IRON-SEC-14": "A02:2021",  # 加密失败
    "IRON-SEC-15": "A02:2021",  # 加密失败
    "IRON-SEC-16": "A05:2021",  # 安全配置错误
}


@dataclass
class GovernanceViolation:
    """治理违规项"""
    rule_id: str           # 规则编号（如 IRON-01）
    rule_name: str         # 规则名称
    category: str          # 分类：architecture / change / quality / security / pitfall
    severity: str          # critical / high / medium / low
    file_path: str         # 违规文件
    line_number: int       # 行号
    line_content: str      # 违规行内容
    detail: str            # 详细说明
    suggestion: str        # 修复建议
    pattern: str = ""      # 匹配到的错题本模式名


@dataclass
class GovernanceReport:
    """治理审计报告"""
    project_path: str
    total_files: int
    total_lines: int
    violations: List[GovernanceViolation] = field(default_factory=list)

    @property
    def blocker_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == "blocker")

    @property
    def critical_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == "critical")

    @property
    def high_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == "high")

    @property
    def medium_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == "medium")

    @property
    def low_count(self) -> int:
        return sum(1 for v in self.violations if v.severity == "low")

    @property
    def total_violations(self) -> int:
        return len(self.violations)

    @property
    def clean_score(self) -> int:
        """治理健康分（0-100）"""
        if self.total_files == 0:
            return 100
        penalty = self.blocker_count * 25 + self.critical_count * 15 + self.high_count * 5 + self.medium_count * 2 + self.low_count * 0.5
        return max(0, min(100, 100 - int(penalty / max(self.total_files, 1) * 10)))


# ═══════════════════════════════════════════════════════════════════
# 治理审计器
# ═══════════════════════════════════════════════════════════════════

class GovernanceAuditor:
    """
    代码治理审计器

    按 5 大维度扫描代码库，检测铁律违反和错题本模式。
    所有检测基于正则/AST 静态分析，不依赖 LLM。
    """

    # ─── 安全铁律：高危模式 ────────────────────────────────────────

    # 硬编码密钥/密码/Token（使用 \b 单词边界防止子串误匹配）
    HARDCODED_SECRET_PATTERNS = [
        # 只匹配字面值（引号内的值），不匹配变量引用/函数调用
        (re.compile(r'\b(?:password|passwd|pwd|secret|token|api_key|apikey|access_key|private_key)\b\s*[:=]\s*["\'][^"\']{8,}["\']', re.IGNORECASE),
         "IRON-SEC-01", "硬编码凭据", "critical",
         "代码中直接写入了密码/Token/密钥等敏感凭据，应改用环境变量或密钥管理服务"),
    ]

    # 凭据检测的排除模式（匹配后仍需要二次验证）
    # 这些模式指示变量引用而非字面值，应排除
    SECRET_EXCLUDE_PATTERNS = [
        # 函数调用：token = create_access_token(...) 或 token = getToken()
        re.compile(r'[:=]\s*\w+\s*\(', re.IGNORECASE),
        # 对象属性访问：self.config.xxx, self.xxx
        re.compile(r'self\.\w+', re.IGNORECASE),
        # 配置字典访问：config["key"], config.get("key")
        re.compile(r'(?:config|settings|cfg)\s*\[', re.IGNORECASE),
        re.compile(r'(?:config|settings|cfg)\.get\s*\(', re.IGNORECASE),
        # 环境变量：os.environ / os.getenv / process.env
        re.compile(r'os\.(?:environ|getenv)', re.IGNORECASE),
        re.compile(r'process\.env', re.IGNORECASE),
        # .env 文件引用
        re.compile(r'\.env\b', re.IGNORECASE),
        # 注释（Python # 或 JS //）
        re.compile(r'^\s*#', re.IGNORECASE),
        re.compile(r'^\s*//', re.IGNORECASE),
        # 错误码常量：E1001_KEY = "E1001_KEY"
        re.compile(r'^[A-Z_]{4,}\s*=\s*["\'][A-Z_\d]+["\']', re.IGNORECASE),
        # 错误码/错误常量名
        re.compile(r'MISSING_|_MISSING|ERROR_|E\d{3,}', re.IGNORECASE),
        # 从 localStorage/sessionStorage 获取（JS/TS）
        re.compile(r'(?:localStorage|sessionStorage)\.(?:get|getItem)', re.IGNORECASE),
        # 函数返回值赋值：token = get_xxx() 或 const token = getXxx()
        re.compile(r'=\s*\w+\s*\(\s*\)', re.IGNORECASE),
    ]

    # SQL 注入风险
    SQL_INJECTION_PATTERNS = [
        (re.compile(r'(?:execute|cursor\.execute|\.raw)\s*\(\s*(?:f["\']|["\'].*%.*["\'])', re.IGNORECASE),
         "IRON-SEC-02", "SQL注入风险", "critical",
         "使用字符串拼接/f-string构造SQL，存在SQL注入风险。应使用参数化查询"),
        (re.compile(r'(?:execute|cursor\.execute)\s*\(\s*["\'].*\{\s*\}.*["\']', re.IGNORECASE),
         "IRON-SEC-02", "SQL注入风险", "critical",
         "使用字符串格式化构造SQL，存在SQL注入风险。应使用参数化查询"),
    ]

    # 命令注入风险
    COMMAND_INJECTION_PATTERNS = [
        (re.compile(r'(?:os\.system|subprocess\.call|subprocess\.Popen|eval|exec)\s*\(\s*.*\+', re.IGNORECASE),
         "IRON-SEC-03", "命令注入风险", "high",
         "使用字符串拼接构造系统命令，存在命令注入风险。应使用subprocess.run(list) + shlex.quote()"),
        (re.compile(r'(?:os\.system|subprocess\.call|subprocess\.Popen)\s*\(\s*(?:f["\'])', re.IGNORECASE),
         "IRON-SEC-03", "命令注入风险", "high",
         "使用f-string构造系统命令，存在命令注入风险。应使用subprocess.run(list)"),
    ]

    # 不安全的反序列化
    UNSAFE_DESERIALIZE = [
        (re.compile(r'pickle\.(?:load|loads)\s*\(', re.IGNORECASE),
         "IRON-SEC-04", "不安全反序列化", "high",
         "pickle.load/loads 可被利用执行任意代码。应使用 json 或安全的序列化格式"),
        (re.compile(r'yaml\.(?:load|full_load)\s*\(', re.IGNORECASE),
         "IRON-SEC-04", "不安全反序列化", "high",
         "yaml.load 可被利用执行任意代码。应使用 yaml.safe_load()"),
    ]

    # 硬编码 URL/端口
    HARDCODED_NETWORK = [
        (re.compile(r'(?:url|host|endpoint|base_url|api_url)\s*[:=]\s*["\']https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', re.IGNORECASE),
         "IRON-SEC-05", "硬编码内网地址", "medium",
         "代码中硬编码了IP地址，部署时容易遗漏修改。应使用配置文件或环境变量"),
    ]

    # 危险协议/函数检测（marshal、eval、exec 等可执行任意代码的函数）
    DANGEROUS_FUNCTIONS = [
        (re.compile(r'marshal\.loads?\s*\(', re.IGNORECASE),
         "IRON-SEC-06", "危险函数调用(marshal)", "critical",
         "marshal.load/loads 可被恶意构造的数据触发任意代码执行。通俗解释：marshal 就像把压缩包解压后自动运行里面的程序，坏人可以伪造压缩包让你的电脑执行恶意代码。",
         "改用 json.loads() 或 msgpack 等安全的序列化格式，并始终用 try-except 包裹"),
        (re.compile(r'\beval\s*\(', re.IGNORECASE),
         "IRON-SEC-06", "危险函数调用(eval)", "critical",
         "eval() 会将字符串当作代码执行，攻击者可通过输入注入恶意代码。通俗解释：eval 就像让别人直接在你的电脑上敲命令，你不知道对方会敲什么。",
         "使用 ast.literal_eval() 替代 eval()，或完全避免动态执行。如果必须使用，对输入做严格白名单校验"),
        (re.compile(r'(?<!\.)\bexec\s*\(', re.IGNORECASE),
         "IRON-SEC-06", "危险函数调用(exec)", "critical",
         "exec() 会执行任意 Python 代码，是最高危的函数之一。通俗解释：exec 比 eval 更危险，相当于把家门钥匙和保险柜密码一起给了陌生人。",
         "几乎永远不应该使用 exec()。如果确需动态代码执行，考虑使用受限的沙箱环境"),
    ]

    # 不安全的子进程调用（shell=True 未校验参数）
    UNSAFE_SUBPROCESS = [
        (re.compile(r'subprocess\.(?:call|Popen|run)\s*\([^)]*shell\s*=\s*True', re.IGNORECASE),
         "IRON-SEC-07", "不安全的子进程调用(shell=True)", "high",
         "shell=True 会启动系统 shell 解释命令字符串，攻击者可注入额外命令（如 ; rm -rf /）。通俗解释：shell=True 就像把命令写在纸条上交给一个不检查内容的人去执行，坏人可以在纸条上加料。",
         "去掉 shell=True，改用列表形式传递参数：subprocess.run(['cmd', 'arg1', 'arg2'])。如果必须用 shell，使用 shlex.quote() 转义所有用户输入"),
        (re.compile(r'os\.system\s*\([^)]*\+', re.IGNORECASE),
         "IRON-SEC-07", "不安全的子进程调用(os.system)", "high",
         "os.system() 直接调用系统 shell，且通过字符串拼接构造命令，极易被注入。通俗解释：os.system 是直接对操作系统喊话，如果喊的内容里混入了用户输入，坏人可以让系统执行任意命令。",
         "使用 subprocess.run() 替代 os.system()，参数以列表形式传递"),
    ]

    # 不安全的文件操作（路径遍历风险）
    PATH_TRAVERSAL = [
        (re.compile(r'os\.(?:remove|unlink|rmdir)\s*\([^)]*\+', re.IGNORECASE),
         "IRON-SEC-08", "路径遍历风险(拼接删除)", "high",
         "使用字符串拼接构造文件删除路径，攻击者可通过 ../ 跳出预期目录，删除系统关键文件。通俗解释：如果让用户输入文件名然后直接删除，坏人可以输入 ../../windows/system32/xxx 来删除系统文件。",
         "使用 os.path.realpath() 规范化路径后，验证路径是否在允许的目录范围内。或使用 pathlib.Path.resolve()"),
        (re.compile(r'\.\.\/|\.\.\\\\', re.IGNORECASE),
         "IRON-SEC-08", "路径遍历风险(../)", "high",
         '代码中出现了 ../ 或 ..\\ 路径遍历模式，如果与用户输入拼接，存在目录穿越攻击风险。通俗解释：../ 在文件路径中表示"上一级目录"，坏人可以用它跳出你的工作目录，访问到不该访问的文件。',
         "使用 os.path.realpath() 或 Path.resolve() 规范化路径，验证最终路径是否在允许的基准目录内"),
    ]

    # 弱加密算法（MD5/SHA1/RC4）- 排除 hashlib. 前缀（由 IRON-SEC-14 专门处理）
    WEAK_CRYPTO = [
        (re.compile(r'(?<!hashlib\.)\b(?:MD5|SHA1|RC4|DES)\b', re.IGNORECASE),
         "IRON-SEC-10", "弱加密算法", "high",
         "使用了已知不安全的加密算法（MD5/SHA1/RC4/DES）。这些算法已被破解或不推荐使用。",
         "使用 SHA-256 或更高级别算法替代。对于密码存储，使用 bcrypt/scrypt/argon2。"),
    ]

    # SSRF 风险（requests.get/urllib 使用用户输入 URL）
    SSRF_PATTERNS = [
        (re.compile(r'(?:requests|urllib|httpx)\.(?:get|post|request)\s*\([^)]*\+\s*', re.IGNORECASE),
         "IRON-SEC-11", "SSRF风险", "high",
         "使用字符串拼接构造 HTTP 请求 URL，攻击者可注入内网地址进行 SSRF 攻击。",
         "对用户输入的 URL 做白名单校验，禁止访问内网地址（127.0.0.1, 10.x, 172.16-31.x, 192.168.x）"),
    ]

    # XSS 风险（未转义的用户输入输出到 HTML）
    XSS_PATTERNS = [
        (re.compile(r'(?:innerHTML|outerHTML|dangerouslySetInnerHTML|document\.write\s*\()', re.IGNORECASE),
         "IRON-SEC-12", "XSS风险", "high",
         "直接使用 innerHTML/dangerouslySetInnerHTML 设置 HTML 内容，存在 XSS 攻击风险。",
         "使用 textContent 替代 innerHTML，或对用户输入做 HTML 实体转义"),
    ]

    # 不安全随机数（random 模块用于安全场景）
    INSECURE_RANDOM = [
        (re.compile(r'\brandom\.(?:random|randint|choice|sample|shuffle)\b', re.IGNORECASE),
         "IRON-SEC-13", "不安全随机数", "medium",
         "使用 random 模块生成随机数，不适合安全场景（可预测）。",
         "安全场景应使用 secrets 模块（secrets.token_hex, secrets.choice）或 os.urandom()"),
    ]

    # 弱哈希算法（用于密码存储）
    WEAK_HASH = [
        (re.compile(r'\bhashlib\.(?:md5|sha1)\b', re.IGNORECASE),
         "IRON-SEC-14", "弱哈希算法", "medium",
         "使用 MD5/SHA1 哈希算法，不适合密码存储和完整性校验。",
         "密码存储使用 bcrypt/scrypt/argon2。完整性校验使用 SHA-256 起。"),
    ]

    # SSL/TLS 证书验证禁用
    SSL_VERIFY_DISABLED = [
        (re.compile(r'\bverify\s*=\s*False\b', re.IGNORECASE),
         "IRON-SEC-15", "SSL证书验证禁用", "medium",
         "禁用了 SSL/TLS 证书验证（verify=False），容易遭受中间人攻击。",
         "移除 verify=False，使用正确的证书链。仅在内网开发环境保留。"),
    ]

    # 资源耗尽风险（无限制循环/递归/大文件读取）
    RESOURCE_EXHAUSTION = [
        (re.compile(r'while\s+True\s*:', re.IGNORECASE),
         "IRON-SEC-16", "资源耗尽风险(无限循环)", "low",
         "检测到 while True 无限循环，缺少明确的退出条件可能导致资源耗尽。",
         "确保循环有明确的退出条件（break/return），或使用 timeout 机制"),
    ]

    # ===== 非 Python 文件的机密检测 =====
    # 在 .env / .yaml / .json / .toml 文件中扫描机密
    NON_PY_SECRET_EXTENSIONS = {".env", ".yaml", ".yml", ".json", ".toml", ".cfg", ".ini", ".conf"}
    NON_PY_SECRET_MASK_PATTERN = re.compile(
        r'(?:password|passwd|pwd|secret|token|api_key|apikey|access_key|private_key|client_secret)\s*[:=]\s*["\']?([^"\'#\s]{8,})["\']?', re.IGNORECASE
    )

    # 敏感信息泄露（日志/调试输出中暴露敏感变量）
    SENSITIVE_LOG = [
        (re.compile(r'(?:print|log(?:ger)?\.(?:debug|info|warning|error)|console\.log)\s*\([^)]*\b(?:password|passwd|pwd|secret|token|api_key|apikey|access_key|private_key)\b', re.IGNORECASE),
         "IRON-SEC-09", "敏感信息泄露(日志输出)", "medium",
         "调试/日志输出中包含了密码、Token、密钥等敏感信息，一旦日志泄露，攻击者可直接获取凭据。通俗解释：把密码打印到日志里，就像把银行卡密码写在快递单上——任何看到这张单子的人都能用你的卡。",
         "移除调试输出中的敏感变量，或使用脱敏函数（如显示前2位+***）替代完整输出。生产环境日志级别应设为 INFO 以上"),
        (re.compile(r'(?:print|log(?:ger)?\.(?:debug|info|warning|error)|console\.log)\s*\(\s*["\'][^"\']*\b(?:password|token|secret|key)\b[^"\']*["\']', re.IGNORECASE),
         "IRON-SEC-09", "敏感信息泄露(明文输出)", "medium",
         "日志字符串中明文包含了 'password'、'token' 等敏感词汇，可能是误将敏感信息输出。通俗解释：即使日志里没有真的密码，包含 'password' 字样也会引起攻击者的注意，让他们知道去哪找。",
         "检查此处是否确实输出敏感信息，若是则立即移除；若为普通描述文字，建议改用更中性的措辞"),
    ]

    # 不安全的反序列化扩展（json 无异常处理、XML 外部实体注入）
    UNSAFE_DESERIALIZE_EXTENDED = [
        (re.compile(r'json\.loads?\s*\(', re.IGNORECASE),
         "IRON-SEC-10", "不安全反序列化(json无异常处理)", "medium",
         "json.loads() 未包裹在 try-except 中，遇到格式错误或恶意构造的 JSON 数据时会导致程序崩溃。通俗解释：json.loads 就像拆包裹，如果包裹里有炸弹（格式错误的数据），没有防护措施的话整个程序就会炸掉。",
         "用 try-except json.JSONDecodeError 包裹 json.loads() 调用，并记录异常日志"),
        (re.compile(r'(?:xml\.etree\.ElementTree|xml\.dom\.minidom|xml\.sax)\s*\.\s*parse', re.IGNORECASE),
         "IRON-SEC-10", "不安全反序列化(XXE漏洞)", "high",
         'XML 解析器默认允许外部实体（XXE），攻击者可通过构造恶意 XML 读取服务器文件、发起 SSRF 攻击。通俗解释：XML 解析器在处理文件时，会"听话地"去读取文件里指向的外部资源，坏人可以利用这一点偷看服务器上的文件。',
         "使用 defusedxml 库替代标准 xml 库，或设置 parser 禁用外部实体：parser.entity = False"),
        (re.compile(r'(?:from\s+xml\.etree|import\s+xml\.etree|from\s+xml\.dom|import\s+xml\.dom)', re.IGNORECASE),
         "IRON-SEC-10", "不安全反序列化(XML导入)", "high",
         "代码中导入了 xml.etree 或 xml.dom 模块。Python 标准 XML 库默认不安全，存在 XXE 和 Billion Laughs 攻击风险。通俗解释：Python 自带的 XML 处理工具就像没装杀毒软件的电脑，处理恶意 XML 文件时会被攻击。",
         "安装并使用 defusedxml 库替代标准 xml 库：pip install defusedxml，然后 from defusedxml import ElementTree"),
    ]

    # ─── 错题本模式 ────────────────────────────────────────────────

    # 空 catch / 裸 except
    PITFALL_EMPTY_EXCEPT = [
        (re.compile(r'except\s*(?:\w+\s*)?(?:as\s+\w+\s*)?:\s*\n\s*(?:pass|continue|return\s+None)\s*$', re.MULTILINE),
         "PITFALL-01", "空异常处理", "high",
         "异常被静默吞噬（pass/continue），问题被隐藏。应至少记录日志或明确处理"),
        (re.compile(r'except\s*:\s*\n\s*(?:pass|continue)', re.MULTILINE),
         "PITFALL-01", "裸except", "high",
         "裸 except 会捕获 KeyboardInterrupt 等系统异常。应指定具体异常类型"),
    ]

    # 可变默认参数
    PITFALL_MUTABLE_DEFAULT = [
        (re.compile(r'def\s+\w+\s*\([^)]*=\s*(?:\[\s*\]|\{\s*\}|set\s*\(\s*\))', re.IGNORECASE),
         "PITFALL-02", "可变默认参数", "medium",
         "默认参数使用了可变对象（[]/{}），多次调用会共享同一实例。应使用 None + 内部初始化"),
    ]

    # 不安全的文件操作
    PITFALL_UNSAFE_FILE = [
        (re.compile(r'open\s*\([^)]*\)\s*\.\s*(?:read|write|readlines)', re.IGNORECASE),
         "PITFALL-03", "未使用上下文管理器", "medium",
         "文件操作未使用 with 语句，可能导致资源泄漏。应使用 with open() as f:"),
        (re.compile(r'os\.remove\s*\(|os\.rmdir\s*\(|shutil\.rmtree\s*\(', re.IGNORECASE),
         "PITFALL-04", "危险删除操作", "medium",
         "直接删除文件/目录，批量操作可能导致数据丢失。确认有备份机制"),
    ]

    # 竞态条件
    PITFALL_RACE_CONDITION = [
        (re.compile(r'os\.path\.exists\s*\([^)]+\)\s*\n.*open\s*\(', re.IGNORECASE),
         "PITFALL-05", "TOCTOU竞态", "medium",
         "先检查文件存在再打开，存在 TOCTOU 竞态条件。应直接尝试打开并捕获异常"),
    ]

    # 不安全的线程操作
    PITFALL_THREAD_UNSAFE = [
        (re.compile(r'threading\.Thread\s*\([^)]*\)\s*\.\s*start\s*\(\s*\)', re.IGNORECASE),
         "PITFALL-06", "裸线程启动", "low",
         "直接使用 threading.Thread 未做线程管理。建议使用 ThreadPoolExecutor 或守护线程"),
    ]

    # I/O 反模式
    PITFALL_IO_PATTERNS = [
        # 一次性读取整个文件到内存（不包含 with 上下文管理器中的操作）
        (re.compile(r'open\s*\([^)]*\)\s*\.\s*(?:read|readlines)\s*\(\s*\)', re.IGNORECASE),
         "PITFALL-07", "一次性读取整个文件", "medium",
         "一次性读取整个文件到内存。大文件应使用逐行迭代或指定 buffering 参数"),
        # 文件操作未使用 with 语句
        (re.compile(r'(\w+)\s*=\s*open\s*\(', re.IGNORECASE),
         "PITFALL-08", "文件未使用with", "medium",
         "文件打开后未使用 with 语句管理，可能导致资源泄漏。应使用 with open() as f:"),
    ]

    # ─── 质量铁律 ──────────────────────────────────────────────────

    # 函数过长（>100行）
    FUNCTION_TOO_LONG = 100

    # 参数过多（>8个）
    FUNCTION_TOO_MANY_PARAMS = 8

    # 嵌套过深（>4层）
    NESTING_TOO_DEEP = 4

    # ─── 架构铁律：依赖方向检测 ────────────────────────────────────

    # 允许的层级依赖方向（低层不应该依赖高层）
    # 注意：这是默认规则，可通过配置文件覆盖。
    # 开源项目可通过 .coderef_governance.json 自定义层级规则。
    LAYER_RULES = {
        "entry": ["core", "data", "shared", "other"],
        "core": ["data", "shared", "other"],
        "data": ["shared", "other"],
        "shared": ["other"],
        "other": [],
    }

    # 层级→目录名映射（默认值，可通过 LLM 分析覆盖）
    # 开源项目不应依赖此映射，应通过 LLM 分析代码内容动态分类。
    DEFAULT_LAYER_PATTERNS = {
        "entry": ["route", "routes", "controller", "controllers", "handler", "handlers",
                   "api", "view", "views", "gui", "window"],
        "core": ["service", "services", "core", "engine", "business", "logic", "domain", "agent"],
        "data": ["model", "models", "data", "db", "database", "store", "repo",
                  "repository", "entity", "entities", "schema", "schemas"],
        "shared": ["util", "utils", "shared", "common", "config", "helper", "helpers", "lib"],
    }

    def __init__(self):
        pass

    def audit(self, project_path: str) -> str:
        """
        执行治理审计

        Args:
            project_path: 项目路径

        Returns:
            Markdown 格式的治理审计报告
        """
        from core.code_analyzer import CodeAnalyzer

        logger.info(f"[GovernanceAudit] 开始扫描: {project_path}")

        # 加载项目专属的 cache 硬编码优化（白名单）
        from core.shared_filter import SharedFilter
        SharedFilter.load_cache(project_path)

        # 1. 基础分析
        analyzer = CodeAnalyzer()
        analysis = analyzer.analyze_project(project_path)

        violations = []

        # 2. 逐文件检测
        for cf in analysis.files:
            # 安全铁律
            violations.extend(self._check_security(cf))
            # 错题本模式
            violations.extend(self._check_pitfalls(cf))
            # 异步函数中同步阻塞（AST 级别检测）
            violations.extend(self._check_async_blocking(cf))
            # 质量铁律
            violations.extend(self._check_quality(cf))

        # 3. 架构铁律（跨文件分析）
        violations.extend(self._check_architecture(analysis))

        # 3.5 非 Python 文件机密扫描（.env/.yaml/.json/.toml等）
        violations.extend(self._scan_non_py_secrets(project_path))

        # 3.7 集中过滤 cache 白名单（确保所有违规都经过白名单检查）
        #    注意：_check_security 内部也有过滤，这里做集中兜底
        from core.cache_manager import cache_manager
        cache_manager.load_hardcoded(project_path)
        logger.info(f"[GovernanceAudit] 白名单已加载，安全规则白名单条目数: {sum(len(v) for v in cache_manager._security_whitelist.values())}")
        violations = [
            v for v in violations
            if not cache_manager.is_security_whitelisted(v.rule_id, v.file_path, v.line_number)
        ]

        # 4. 构建报告
        self.violations = violations
        report = GovernanceReport(
            project_path=project_path,
            total_files=analysis.total_files,
            total_lines=analysis.total_lines,
            violations=violations,
        )
        self.report = report

        logger.info(f"[GovernanceAudit] 审计完成: {len(violations)} 条违规 "
                     f"(critical={report.critical_count}, high={report.high_count}, "
                     f"medium={report.medium_count}, low={report.low_count}) "
                     f"健康分={report.clean_score}")

        return self._generate_report(report)

    def _get_docstring_lines(self, lines: List[str]) -> set:
        """委托给 SharedFilter"""
        return _sf.get_docstring_lines(lines)

    def _is_credential_false_positive(self, line: str) -> bool:
        """判断硬编码凭据匹配是否为误报"""
        # 1. 如果行是正则模式（包含 r' 或 r"），跳过
        #    注意：需要覆盖所有关键词，不只是 password
        if re.search(r"""r['"].*(?:password|passwd|pwd|secret|token|api_key|apikey|access_key|private_key)""", line, re.IGNORECASE):
            return True
        # 2. 如果行是函数定义或 lambda，匹配的是参数名而非值
        if re.search(r'def\s+\w+\s*\(', line) or re.search(r'lambda\s+', line):
            return True
        # 3. 如果行包含 self.config、self._config、os.environ、os.getenv
        if re.search(r'self\.(?:config|_config|settings|_settings|cfg)|os\.environ|os\.getenv|getenv\(', line):
            return True
        # 3b. 如果行是配置对象的属性访问（cfg.xxx、config.xxx、settings.xxx）
        if re.search(r'\b(?:cfg|config|settings)\.\w+', line):
            return True
        # 3c. 如果行是函数调用且参数名与值相同（api_key=api_key, base_url=base_url）
        if re.search(r'\b(api_key|apikey|secret|token|password|passwd|pwd|base_url|access_key|private_key)\s*=\s*\1\b', line, re.IGNORECASE):
            return True
        # 4. 如果行是注释（以 # 开头）
        stripped = line.strip()
        if stripped.startswith('#'):
            return True
        # 5. 如果行是类型注解或接口定义（不含实际赋值）
        if re.match(r'^\s*\w+\s*:\s*(Optional|str|Dict|List|Tuple|Any|Union)', line):
            return True
        # 6. 如果行是文档字符串的一部分
        if stripped.startswith('"""') or stripped.startswith("'''"):
            return True
        # 7. 如果值是纯变量名引用（非字符串字面量），排除
        #    例如: api_key=env_key, token=my_token
        if re.search(r'\b(?:password|passwd|pwd|secret|token|api_key|apikey|access_key|private_key)\b\s*=\s*([a-zA-Z_]\w*)\s*[,)]?\s*$', line, re.IGNORECASE):
            return True
        # 8. GUI 组件创建（如 QLineEdit()）
        if re.search(r'=\s*Q\w+\(\)', line):
            return True
        # 9. 值是对象属性访问（如 request.api_key, cfg.xxx）
        if re.search(r'\b(?:password|passwd|pwd|secret|token|api_key|apikey|access_key|private_key)\b\s*=\s*\w+\.\w+', line, re.IGNORECASE):
            return True
        return False

    def _is_pattern_def_line(self, line: str) -> bool:
        """委托给 SharedFilter"""
        return _sf.is_pattern_def_line(line)

    def _is_sensitive_log_false_positive(self, line: str) -> bool:
        """判断敏感日志匹配是否为误报（仅描述性提到 API Key，非实际泄露）"""
        stripped = line.strip()
        # 日志消息中仅包含 "API Key" 作为描述性文字（如 "未设置API Key"）
        if re.search(r'(?:logger\.|print\s*\()\s*[^,)]*["\'][^"\']*(?:未设置|占位符|暂不可用|not\s+(?:set|available|configured)|empty|placeholder|skip|跳过)[^"\']*["\']', stripped, re.IGNORECASE):
            return True
        # 日志消息中提到 "api_key" 字样但只是描述状态
        if re.search(r'logger\.(?:debug|info|warning|error)\s*\(\s*f?["\'].*\b(?:api_key|API\s*Key)\b.*(?:占位符|跳过|空|暂不可用|not\s+(?:set|available|configured))', stripped, re.IGNORECASE):
            return True
        return False

    def _is_command_injection_false_positive(self, line: str) -> bool:
        """判断命令注入匹配是否为误报（参数是内部路径而非用户输入）"""
        stripped = line.strip()
        # Popen/explorer 打开内部路径（self.xxx, 非用户输入）
        if re.search(r'self\.\w+', stripped, re.IGNORECASE):
            return True
        # Popen 中使用 os.path 构造的路径
        if re.search(r'os\.path\.\w+', stripped, re.IGNORECASE):
            return True
        return False

    def _is_json_in_try_block(self, lines: List[str], line_idx: int) -> bool:
        """委托给 SharedFilter"""
        return _sf.is_in_try_block(lines, line_idx)

    def _check_security(self, cf) -> List[GovernanceViolation]:
        """检测安全铁律违规"""
        violations = []
        lines = cf.raw_content.splitlines() if cf.raw_content else []

        # 预解析文档字符串范围，跳过其中的所有安全检测
        docstring_lines = self._get_docstring_lines(lines)

        for i, line in enumerate(lines, 1):
            line_stripped = line.strip()

            # 跳过文档字符串行（所有检测）
            if i in docstring_lines:
                continue

            # 跳过注释行（所有检测）
            if line_stripped.startswith("#") or line_stripped.startswith("//"):
                continue

            # 跳过安全检测规则定义行（字符串中的代码模式）
            is_pattern_def = self._is_pattern_def_line(line_stripped)

            # 硬编码凭据
            for pattern, rule_id, rule_name, severity, detail in self.HARDCODED_SECRET_PATTERNS:
                if pattern.search(line_stripped):
                    # 排除配置读取、环境变量、注释
                    if any(ep.search(line_stripped) for ep in self.SECRET_EXCLUDE_PATTERNS):
                        continue
                    # 上下文过滤：排除正则模式、函数参数、配置读取等误报
                    if self._is_credential_false_positive(line_stripped):
                        continue
                    violations.append(GovernanceViolation(
                        rule_id=rule_id, rule_name=rule_name, category="security",
                        severity=severity, file_path=cf.file_path, line_number=i,
                        line_content=line_stripped[:120],
                        detail=detail,
                        suggestion="将凭据移到环境变量或密钥管理服务（如 Vault/AWS Secrets Manager）",
                    ))

            # SQL 注入
            for pattern, rule_id, rule_name, severity, detail in self.SQL_INJECTION_PATTERNS:
                if pattern.search(line_stripped):
                    violations.append(GovernanceViolation(
                        rule_id=rule_id, rule_name=rule_name, category="security",
                        severity=severity, file_path=cf.file_path, line_number=i,
                        line_content=line_stripped[:120],
                        detail=detail,
                        suggestion="使用参数化查询（如 ? 占位符 + 参数元组）",
                    ))

            # 命令注入
            for pattern, rule_id, rule_name, severity, detail in self.COMMAND_INJECTION_PATTERNS:
                if pattern.search(line_stripped):
                    if self._is_command_injection_false_positive(line_stripped):
                        continue
                    violations.append(GovernanceViolation(
                        rule_id=rule_id, rule_name=rule_name, category="security",
                        severity=severity, file_path=cf.file_path, line_number=i,
                        line_content=line_stripped[:120],
                        detail=detail,
                        suggestion="使用 subprocess.run([cmd, arg1, arg2]) + shlex.quote()",
                    ))

            # 不安全反序列化
            if not is_pattern_def:
                for pattern, rule_id, rule_name, severity, detail in self.UNSAFE_DESERIALIZE:
                    if pattern.search(line_stripped):
                        violations.append(GovernanceViolation(
                            rule_id=rule_id, rule_name=rule_name, category="security",
                            severity=severity, file_path=cf.file_path, line_number=i,
                            line_content=line_stripped[:120],
                            detail=detail,
                            suggestion="使用 json.loads() 或 yaml.safe_load() 替代",
                        ))

            # 硬编码网络地址
            for pattern, rule_id, rule_name, severity, detail in self.HARDCODED_NETWORK:
                if pattern.search(line_stripped):
                    violations.append(GovernanceViolation(
                        rule_id=rule_id, rule_name=rule_name, category="security",
                        severity=severity, file_path=cf.file_path, line_number=i,
                        line_content=line_stripped[:120],
                        detail=detail,
                        suggestion="将 IP 地址移到配置文件或环境变量中",
                    ))

            # 危险函数调用（marshal、eval、exec）
            if not is_pattern_def:
                for pattern, rule_id, rule_name, severity, detail, suggestion in self.DANGEROUS_FUNCTIONS:
                    if pattern.search(line_stripped):
                        violations.append(GovernanceViolation(
                            rule_id=rule_id, rule_name=rule_name, category="security",
                            severity=severity, file_path=cf.file_path, line_number=i,
                            line_content=line_stripped[:120],
                            detail=detail,
                            suggestion=suggestion,
                        ))

            # 不安全的子进程调用（shell=True）
            for pattern, rule_id, rule_name, severity, detail, suggestion in self.UNSAFE_SUBPROCESS:
                if pattern.search(line_stripped):
                    violations.append(GovernanceViolation(
                        rule_id=rule_id, rule_name=rule_name, category="security",
                        severity=severity, file_path=cf.file_path, line_number=i,
                        line_content=line_stripped[:120],
                        detail=detail,
                        suggestion=suggestion,
                    ))

            # 路径遍历风险
            if not is_pattern_def:
                for pattern, rule_id, rule_name, severity, detail, suggestion in self.PATH_TRAVERSAL:
                    if pattern.search(line_stripped):
                        violations.append(GovernanceViolation(
                            rule_id=rule_id, rule_name=rule_name, category="security",
                            severity=severity, file_path=cf.file_path, line_number=i,
                            line_content=line_stripped[:120],
                            detail=detail,
                            suggestion=suggestion,
                        ))

            # 弱加密算法
            if not is_pattern_def:
                for pattern, rule_id, rule_name, severity, detail, suggestion in self.WEAK_CRYPTO:
                    if pattern.search(line_stripped):
                        violations.append(GovernanceViolation(
                            rule_id=rule_id, rule_name=rule_name, category="security",
                            severity=severity, file_path=cf.file_path, line_number=i,
                            line_content=line_stripped[:120],
                            detail=detail,
                            suggestion=suggestion,
                        ))

            # SSRF
            if not is_pattern_def:
                for pattern, rule_id, rule_name, severity, detail, suggestion in self.SSRF_PATTERNS:
                    if pattern.search(line_stripped):
                        violations.append(GovernanceViolation(
                            rule_id=rule_id, rule_name=rule_name, category="security",
                            severity=severity, file_path=cf.file_path, line_number=i,
                            line_content=line_stripped[:120],
                            detail=detail,
                            suggestion=suggestion,
                        ))

            # XSS
            if not is_pattern_def:
                for pattern, rule_id, rule_name, severity, detail, suggestion in self.XSS_PATTERNS:
                    if pattern.search(line_stripped):
                        violations.append(GovernanceViolation(
                            rule_id=rule_id, rule_name=rule_name, category="security",
                            severity=severity, file_path=cf.file_path, line_number=i,
                            line_content=line_stripped[:120],
                            detail=detail,
                            suggestion=suggestion,
                        ))

            # 不安全随机数
            if not is_pattern_def:
                for pattern, rule_id, rule_name, severity, detail, suggestion in self.INSECURE_RANDOM:
                    if pattern.search(line_stripped):
                        violations.append(GovernanceViolation(
                            rule_id=rule_id, rule_name=rule_name, category="security",
                            severity=severity, file_path=cf.file_path, line_number=i,
                            line_content=line_stripped[:120],
                            detail=detail,
                            suggestion=suggestion,
                        ))

            # 弱哈希算法
            if not is_pattern_def:
                for pattern, rule_id, rule_name, severity, detail, suggestion in self.WEAK_HASH:
                    if pattern.search(line_stripped):
                        violations.append(GovernanceViolation(
                            rule_id=rule_id, rule_name=rule_name, category="security",
                            severity=severity, file_path=cf.file_path, line_number=i,
                            line_content=line_stripped[:120],
                            detail=detail,
                            suggestion=suggestion,
                        ))

            # SSL 证书验证禁用
            if not is_pattern_def:
                for pattern, rule_id, rule_name, severity, detail, suggestion in self.SSL_VERIFY_DISABLED:
                    if pattern.search(line_stripped):
                        violations.append(GovernanceViolation(
                            rule_id=rule_id, rule_name=rule_name, category="security",
                            severity=severity, file_path=cf.file_path, line_number=i,
                            line_content=line_stripped[:120],
                            detail=detail,
                            suggestion=suggestion,
                        ))

            # 资源耗尽
            if not is_pattern_def:
                for pattern, rule_id, rule_name, severity, detail, suggestion in self.RESOURCE_EXHAUSTION:
                    if pattern.search(line_stripped):
                        violations.append(GovernanceViolation(
                            rule_id=rule_id, rule_name=rule_name, category="security",
                            severity=severity, file_path=cf.file_path, line_number=i,
                            line_content=line_stripped[:120],
                            detail=detail,
                            suggestion=suggestion,
                        ))

            # 敏感信息泄露（日志/调试输出）
            if not is_pattern_def:
                for pattern, rule_id, rule_name, severity, detail, suggestion in self.SENSITIVE_LOG:
                    if pattern.search(line_stripped):
                        # 过滤：仅包含 "api_key" / "API Key" 作为描述性文字的日志
                        if self._is_sensitive_log_false_positive(line_stripped):
                            continue
                        violations.append(GovernanceViolation(
                            rule_id=rule_id, rule_name=rule_name, category="security",
                            severity=severity, file_path=cf.file_path, line_number=i,
                            line_content=line_stripped[:120],
                            detail=detail,
                            suggestion=suggestion,
                        ))

            # 不安全反序列化扩展（json 无异常处理、XML XXE）
            if not is_pattern_def:
                for pattern, rule_id, rule_name, severity, detail, suggestion in self.UNSAFE_DESERIALIZE_EXTENDED:
                    if pattern.search(line_stripped):
                        # json.load/json.loads 跨行 try-except 检测
                        if 'json.load' in line_stripped and self._is_json_in_try_block(lines, i - 1):
                            continue
                        violations.append(GovernanceViolation(
                            rule_id=rule_id, rule_name=rule_name, category="security",
                            severity=severity, file_path=cf.file_path, line_number=i,
                            line_content=line_stripped[:120],
                            detail=detail,
                            suggestion=suggestion,
                        ))

        # 过滤 cache 白名单（用户标记为可接受的安全规则命中）
        violations = [
            v for v in violations
            if not SharedFilter.is_security_whitelisted(v.rule_id, v.file_path, v.line_number)
        ]

        return violations

    def _check_pitfalls(self, cf) -> List[GovernanceViolation]:
        """检测错题本模式"""
        violations = []
        lines = cf.raw_content.splitlines() if cf.raw_content else []
        content = cf.raw_content if cf.raw_content else ""

        # 空异常处理 / 裸 except
        for pattern, rule_id, rule_name, severity, detail in self.PITFALL_EMPTY_EXCEPT:
            for m in pattern.finditer(content):
                lineno = content[:m.start()].count("\n") + 1
                line = lines[lineno - 1] if lineno <= len(lines) else ""
                # 降级：except Exception: continue 在遍历/初始化场景中属于合理容错
                actual_severity = severity
                exc_line = line.strip()
                if rule_id == "PITFALL-01":
                    # except <Type>: continue → 降级为 low
                    if re.search(r'except\s+\w+\s*:\s*continue', exc_line):
                        actual_severity = "low"
                    # except Empty: → 队列超时，降级为 low
                    if re.search(r'except\s+Empty\s*:', exc_line):
                        actual_severity = "low"
                    # except: return None → 降级为 medium（初始化降级场景）
                    if re.search(r'except\s*:\s*return\s+None', exc_line):
                        actual_severity = "medium"
                violations.append(GovernanceViolation(
                    rule_id=rule_id, rule_name=rule_name, category="pitfall",
                    severity=actual_severity, file_path=cf.file_path, line_number=lineno,
                    line_content=line.strip()[:120],
                    detail=detail,
                    suggestion="至少记录异常日志 logger.exception()，或 re-raise",
                    pattern=rule_name,
                ))

        # 可变默认参数
        for pattern, rule_id, rule_name, severity, detail in self.PITFALL_MUTABLE_DEFAULT:
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    if line.strip().startswith("#"):
                        continue
                    violations.append(GovernanceViolation(
                        rule_id=rule_id, rule_name=rule_name, category="pitfall",
                        severity=severity, file_path=cf.file_path, line_number=i,
                        line_content=line.strip()[:120],
                        detail=detail,
                        suggestion="使用 None 作为默认值，函数内部做 if x is None: x = []",
                        pattern=rule_name,
                    ))

        # 不安全的文件操作
        for pattern, rule_id, rule_name, severity, detail in self.PITFALL_UNSAFE_FILE:
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    if line.strip().startswith("#"):
                        continue
                    violations.append(GovernanceViolation(
                        rule_id=rule_id, rule_name=rule_name, category="pitfall",
                        severity=severity, file_path=cf.file_path, line_number=i,
                        line_content=line.strip()[:120],
                        detail=detail,
                        suggestion="使用 with 语句确保资源正确释放" if "rule_id" == "PITFALL-03" else "确认有备份机制，操作前做二次确认",
                        pattern=rule_name,
                    ))

        # 竞态条件（TOCTOU）
        for pattern, rule_id, rule_name, severity, detail in self.PITFALL_RACE_CONDITION:
            for m in pattern.finditer(content):
                lineno = content[:m.start()].count("\n") + 1
                line = lines[lineno - 1] if lineno <= len(lines) else ""
                violations.append(GovernanceViolation(
                    rule_id=rule_id, rule_name=rule_name, category="pitfall",
                    severity=severity, file_path=cf.file_path, line_number=lineno,
                    line_content=line.strip()[:120],
                    detail=detail,
                    suggestion="直接尝试操作并捕获 FileNotFoundError/PermissionError",
                    pattern=rule_name,
                ))

        # 裸线程
        for pattern, rule_id, rule_name, severity, detail in self.PITFALL_THREAD_UNSAFE:
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    if line.strip().startswith("#"):
                        continue
                    violations.append(GovernanceViolation(
                        rule_id=rule_id, rule_name=rule_name, category="pitfall",
                        severity=severity, file_path=cf.file_path, line_number=i,
                        line_content=line.strip()[:120],
                        detail=detail,
                        suggestion="使用 concurrent.futures.ThreadPoolExecutor 管理线程生命周期",
                        pattern=rule_name,
                    ))

        # I/O 反模式
        for pattern, rule_id, rule_name, severity, detail in self.PITFALL_IO_PATTERNS:
            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    if line.strip().startswith("#"):
                        continue
                    suggestions = {
                        "PITFALL-07": "对大型文件使用 for line in f: 逐行迭代，避免全部加载到内存",
                        "PITFALL-08": "使用 with open() as f: 确保文件正确关闭",
                    }
                    violations.append(GovernanceViolation(
                        rule_id=rule_id, rule_name=rule_name, category="pitfall",
                        severity=severity, file_path=cf.file_path, line_number=i,
                        line_content=line.strip()[:120],
                        detail=detail,
                        suggestion=suggestions.get(rule_id, "优化 I/O 操作模式"),
                        pattern=rule_name,
                    ))

        return violations

    # ─── 异步函数中同步阻塞检测 ────────────────────────────────────

    BLOCKING_CALLS = {
        "time.sleep", "time.sleep_ms", "time.sleep_us",
        "requests.get", "requests.post", "requests.put", "requests.delete",
        "requests.patch", "requests.head",
        "urllib.request.urlopen",
        "socket.connect", "socket.recv", "socket.send",
        "subprocess.run", "subprocess.call", "subprocess.Popen",
        "os.system", "os.popen",
    }

    def _check_async_blocking(self, cf) -> List[GovernanceViolation]:
        """使用 AST 检测异步函数中的同步阻塞调用"""
        violations = []
        if cf.language not in ("Python", "python"):
            return violations
        if not cf.file_path.endswith(".py"):
            return violations
        try:
            import ast
            with open(cf.file_path, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
            tree = ast.parse(source)
        except (SyntaxError, OSError):
            return violations

        for node in ast.walk(tree):
            if not isinstance(node, ast.AsyncFunctionDef):
                continue

            # 查找 async 函数体内的同步阻塞调用
            for child in ast.walk(node):
                if isinstance(child, ast.Call):
                    func_str = self._get_call_string(child)
                    if func_str in self.BLOCKING_CALLS:
                        violations.append(GovernanceViolation(
                            rule_id="PITFALL-09", rule_name="异步函数中同步阻塞",
                            category="pitfall", severity="high",
                            file_path=cf.file_path, line_number=child.lineno,
                            line_content=ast.unparse(child)[:120],
                            detail=f"在 async 函数 {node.name}() 中调用了同步阻塞操作 {func_str}，会阻塞事件循环",
                            suggestion=f"使用异步替代：{func_str.replace('requests.', 'httpx.AsyncClient.').replace('time.sleep', 'asyncio.sleep')}",
                            pattern="异步函数中同步阻塞",
                        ))
        return violations

    @staticmethod
    def _get_call_string(node) -> str:
        """从 AST Call 节点获取完整调用字符串"""
        import ast
        parts = []
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        elif isinstance(func, ast.Attribute):
            current = func
            attr_parts = []
            while isinstance(current, ast.Attribute):
                attr_parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                attr_parts.append(current.id)
            attr_parts.reverse()
            return ".".join(attr_parts)
        return ""

    def _check_quality(self, cf) -> List[GovernanceViolation]:
        """检测质量铁律违规"""
        violations = []
        lines = cf.raw_content.splitlines() if cf.raw_content else []

        # 函数过长
        for func in cf.functions:
            func_lines = func.end_line - func.start_line + 1
            if func_lines > self.FUNCTION_TOO_LONG:
                violations.append(GovernanceViolation(
                    rule_id="IRON-QUAL-01", rule_name="函数过长",
                    category="quality", severity="medium",
                    file_path=cf.file_path, line_number=func.start_line,
                    line_content=f"{func.name}() — {func_lines}行",
                    detail=f"函数 {func.name}() 有 {func_lines} 行，超过 {self.FUNCTION_TOO_LONG} 行阈值。过长函数难以理解和测试。",
                    suggestion=f"拆分为多个职责单一的小函数，每个函数不超过 {self.FUNCTION_TOO_LONG} 行",
                ))

            # 参数过多
            param_count = len(func.parameters) if func.parameters else 0
            if param_count > self.FUNCTION_TOO_MANY_PARAMS:
                violations.append(GovernanceViolation(
                    rule_id="IRON-QUAL-02", rule_name="参数过多",
                    category="quality", severity="medium",
                    file_path=cf.file_path, line_number=func.start_line,
                    line_content=f"{func.name}({param_count}个参数)",
                    detail=f"函数 {func.name}() 有 {param_count} 个参数，超过 {self.FUNCTION_TOO_MANY_PARAMS} 个阈值。过多参数降低可读性。",
                    suggestion="使用数据类/配置对象封装相关参数，或拆分为多个方法",
                ))

        # 嵌套过深
        for i, line in enumerate(lines, 1):
            stripped = line.rstrip()
            indent = len(line) - len(stripped)
            # 缩进级别（4空格=1级）
            indent_level = indent // 4
            if indent_level > self.NESTING_TOO_DEEP and stripped and not stripped.startswith(("#", "//", "/*", "*", "'''", '"""')):
                # 检查是否是真正的嵌套（不是对齐的续行）
                if stripped[0] not in (")", "}", "]", ")", ".", ","):
                    violations.append(GovernanceViolation(
                        rule_id="IRON-QUAL-03", rule_name="嵌套过深",
                        category="quality", severity="low",
                        file_path=cf.file_path, line_number=i,
                        line_content=stripped[:120],
                        detail=f"嵌套深度 {indent_level} 层，超过 {self.NESTING_TOO_DEEP} 层阈值。深层嵌套降低可读性。",
                        suggestion="使用 early return / guard clause 减少嵌套，或提取为子函数",
                    ))
                    # 只报告每个文件的第一处过深嵌套
                    break

        return violations

    def _scan_non_py_secrets(self, project_path: str) -> List[GovernanceViolation]:
        """扫描非 Python 文件中的机密（.env/.yaml/.json/.toml）"""
        violations = []
        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in (
                "__pycache__", "node_modules", ".git", "venv", ".venv", "data",
                "third_party", ".gitnexus", "docs", "reports",
            )]
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext not in self.NON_PY_SECRET_EXTENSIONS:
                    continue
                fpath = os.path.join(root, f)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                        for lineno, line in enumerate(fh, 1):
                            m = self.NON_PY_SECRET_MASK_PATTERN.search(line)
                            if not m:
                                continue
                            value = m.group(1)
                            # 跳过占位符/示例值
                            if value.lower() in ("placeholder", "your_key", "your_token", "xxx", "example",
                                                  "changeme", "replace_me", "your_api_key", "your_secret"):
                                continue
                            # 跳过空值/variable ref
                            if re.match(r'^[\$\{].*[\}\}]$', value):
                                continue
                            violations.append(GovernanceViolation(
                                rule_id="IRON-SEC-01", rule_name="硬编码凭据",
                                category="security", severity="critical",
                                file_path=fpath, line_number=lineno,
                                line_content=line.strip()[:120],
                                detail=f"非代码文件中发现硬编码凭据：{m.group(0)[:60]}",
                                suggestion="将凭据移到环境变量中，或使用 .env.example 作为模板",
                            ))
                except (OSError, IOError, UnicodeDecodeError):
                    pass
        return violations

    def _check_architecture(self, analysis) -> List[GovernanceViolation]:
        """检测架构铁律违规"""
        violations = []

        # 构建模块依赖图
        deps = defaultdict(set)  # file -> set of imported files
        modules = {}  # file -> layer

        for cf in analysis.files:
            module = self._get_module_name(cf.file_path)
            # 传递代码内容以支持 LLM 驱动的层级分类
            raw_content = cf.raw_content if cf.raw_content else ""
            layer = self._classify_layer(cf.file_path, code_content=raw_content[:2000])
            modules[cf.file_path] = layer

            # 提取导入
            flines = cf.raw_content.splitlines() if cf.raw_content else []
            for line in flines:
                imp = self._extract_import(line)
                if imp:
                    deps[cf.file_path].add(imp)

        # 检查层级穿透
        for file_path, layer in modules.items():
            for dep in deps.get(file_path, set()):
                # 尝试匹配导入路径
                matched = self._match_import_to_file(dep, modules.keys())
                for target_file in matched:
                    target_layer = modules.get(target_file, "other")
                    if target_layer == layer:
                        continue
                    allowed = self.LAYER_RULES.get(layer, ["other"])
                    if target_layer not in allowed and target_layer != "other":
                        violations.append(GovernanceViolation(
                            rule_id="IRON-ARCH-01", rule_name="层级穿透",
                            category="architecture", severity="high",
                            file_path=file_path, line_number=0,
                            line_content=f"{layer} → {target_layer} ({dep})",
                            detail=f"{layer} 层直接依赖了 {target_layer} 层，违反了依赖方向规则。{layer} 层只能依赖: {allowed}",
                            suggestion=f"将 {target_layer} 层的逻辑下沉到 {layer} 允许依赖的层级，或通过接口反转依赖",
                        ))

        # 检查循环依赖（简单检测：A imports B and B imports A）
        checked = set()
        for a_file, a_deps in deps.items():
            for b_file in a_deps:
                pair = tuple(sorted([a_file, b_file]))
                if pair in checked:
                    continue
                checked.add(pair)
                b_deps = deps.get(b_file, set())
                if a_file in b_deps:
                    violations.append(GovernanceViolation(
                        rule_id="IRON-ARCH-02", rule_name="循环依赖",
                        category="architecture", severity="high",
                        file_path=a_file, line_number=0,
                        line_content=f"{os.path.basename(a_file)} ↔ {os.path.basename(b_file)}",
                        detail=f"检测到循环依赖：{os.path.basename(a_file)} 和 {os.path.basename(b_file)} 互相导入",
                        suggestion="提取共同依赖到第三个模块，或使用依赖注入打破循环",
                    ))

        return violations

    def _get_module_name(self, file_path: str) -> str:
        """从文件路径提取模块名"""
        return os.path.splitext(os.path.basename(file_path))[0]

    def _classify_layer(self, file_path: str, code_content: str = "") -> str:
        """
        根据文件路径和代码内容分类层级
        
        优先使用 LLM 分析代码内容确定层级（通用方案），
        LLM 不可用时使用默认目录名模式匹配（降级方案）。
        
        开源项目建议：通过 LLM 分析代码内容而非目录名来确定层级，
        这样可以适应任意项目结构。
        """
        fp_lower = file_path.replace("\\", "/").lower()
        parts = fp_lower.split("/")

        # 尝试用 LLM 分析代码内容确定层级
        if code_content and len(code_content) > 30:
            try:
                # 检查代码内容中的关键模式（通用检测，不依赖目录名）
                # 如果导入了 Flask/FastAPI/Django 的 route 装饰器 → entry
                if any(kw in code_content for kw in ['@app.route', '@router.', 'FastAPI', 'Flask',
                                                       'Blueprint', 'APIView', 'def get(', 'def post(',
                                                       'def put(', 'def delete(', 'Response', 'JSONResponse']):
                    return "entry"
                # 如果包含 ORM 模型定义 → data
                if any(kw in code_content for kw in ['class Meta:', 'db.Model', 'BaseModel', 'Table(',
                                                       'Column(', 'session.query', '__tablename__',
                                                       'SQLAlchemy', 'declarative_base']):
                    return "data"
                # 如果包含核心业务逻辑特征 → core
                if re.search(r'class\s+\w*(Service|Engine|Manager|Handler|Agent|Processor)', code_content):
                    return "core"
            except Exception:
                pass

        # 降级：按目录名精确匹配（使用可配置的 DEFAULT_LAYER_PATTERNS）
        for part in reversed(parts):
            for layer, patterns in self.DEFAULT_LAYER_PATTERNS.items():
                if part in patterns:
                    return layer

        return "other"

    def _extract_import(self, line: str) -> Optional[str]:
        """从代码行提取导入路径"""
        line = line.strip()
        # Python import
        m = re.match(r'(?:from|import)\s+([\w.]+)', line)
        if m:
            return m.group(1)
        # JS/TS import
        m = re.match(r'import\s+.*\s+from\s+["\']([^"\']+)["\']', line)
        if m:
            return m.group(1)
        # JS/TS require
        m = re.match(r'(?:const|let|var)\s+\w+\s*=\s*require\s*\(\s*["\']([^"\']+)["\']', line)
        if m:
            return m.group(1)
        return None

    def _match_import_to_file(self, imp: str, all_files: List[str]) -> List[str]:
        """将导入路径匹配到实际文件（严格后缀匹配，避免子串误报）"""
        matched = []
        imp_normalized = imp.replace(".", "/").replace("\\", "/")
        imp_parts = imp_normalized.split("/")
        # 至少需要2级路径才算有效匹配
        if len(imp_parts) < 1:
            return matched

        # 规则：导入路径的最后 N 段必须与文件路径的最后 N 段严格匹配
        for f in all_files:
            f_normalized = f.replace("\\", "/")
            f_parts = f_normalized.split("/")
            # 去掉文件扩展名比较
            f_last = f_parts[-1]
            if "." in f_last:
                f_last = f_last.rsplit(".", 1)[0]
                f_parts[-1] = f_last

            # 方法1：导入路径的最后2段与文件路径的最后2段严格相等
            if len(imp_parts) >= 2 and len(f_parts) >= 2:
                if imp_parts[-1] == f_parts[-1] and imp_parts[-2] == f_parts[-2]:
                    matched.append(f)
                    continue

            # 方法2：导入路径的最后1段与文件路径的最后1段严格相等（仅当导入路径只有1段时）
            if len(imp_parts) == 1 and len(f_parts) >= 1:
                if imp_parts[0] == f_parts[-1]:
                    matched.append(f)
                    continue

        return matched

    def _generate_report(self, report: GovernanceReport) -> str:
        """生成 Markdown 治理审计报告"""
        # 按严重程度排序
        violations = sorted(report.violations,
                            key=lambda v: (SEVERITY_ORDER.get(v.severity, 9), v.file_path, v.line_number))

        # 分类统计
        cat_counts = defaultdict(int)
        sev_counts = defaultdict(int)
        for v in violations:
            cat_counts[v.category] += 1
            sev_counts[v.severity] += 1

        # 健康分颜色
        if report.clean_score >= 80:
            score_emoji = "🟢"
        elif report.clean_score >= 50:
            score_emoji = "🟡"
        else:
            score_emoji = "🔴"

        lines = []
        lines.append(f"# 🔍 代码治理审计报告")
        lines.append(f"")
        lines.append(f"**项目路径**: `{report.project_path}`  ")
        lines.append(f"**扫描范围**: {report.total_files} 个文件, {report.total_lines} 行  ")
        lines.append(f"**治理健康分**: {score_emoji} **{report.clean_score}/100**  ")
        lines.append(f"")

        # 总览
        lines.append(f"## 📊 违规总览")
        lines.append(f"")
        lines.append(f"| 严重程度 | 数量 |")
        lines.append(f"|---------|------|")
        lines.append(f"| 🔴 Critical | {report.critical_count} |")
        lines.append(f"| 🟠 High | {report.high_count} |")
        lines.append(f"| 🟡 Medium | {report.medium_count} |")
        lines.append(f"| ⚪ Low | {report.low_count} |")
        lines.append(f"| **总计** | **{report.total_violations}** |")
        lines.append(f"")

        lines.append(f"| 分类 | 数量 |")
        lines.append(f"|------|------|")
        for cat in ["security", "architecture", "pitfall", "quality"]:
            if cat_counts.get(cat, 0) > 0:
                cat_names = {"security": "安全铁律", "architecture": "架构铁律", "pitfall": "错题本模式", "quality": "质量铁律"}
                lines.append(f"| {cat_names.get(cat, cat)} | {cat_counts[cat]} |")
        lines.append(f"")

        if not violations:
            lines.append(f"✅ **未发现违规项，项目治理状况良好。**")
            return "\n".join(lines)

        # 分类明细
        for cat in ["security", "architecture", "pitfall", "quality"]:
            cat_violations = [v for v in violations if v.category == cat]
            if not cat_violations:
                continue

            cat_names = {
                "security": "🛡️ 安全铁律",
                "architecture": "🏗️ 架构铁律",
                "pitfall": "📋 错题本模式",
                "quality": "📏 质量铁律",
            }

            lines.append(f"## {cat_names.get(cat, cat)}（{len(cat_violations)} 项）")
            lines.append(f"")

            # 每类最多展示 100 条，避免报告过大
            display_count = min(len(cat_violations), 100)
            for v in cat_violations[:display_count]:
                sev_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}.get(v.severity, "⚪")
                lines.append(f"### {sev_icon} [{v.rule_id}] {v.rule_name}")
                lines.append(f"")
                lines.append(f"- **文件**: `{v.file_path}`")
                if v.line_number > 0:
                    lines.append(f"- **行号**: L{v.line_number}")
                lines.append(f"- **代码**: `{v.line_content}`")
                lines.append(f"- **说明**: {v.detail}")
                lines.append(f"- **建议**: {v.suggestion}")
                if v.pattern:
                    lines.append(f"- **错题本模式**: {v.pattern}")
                lines.append(f"")

            if len(cat_violations) > display_count:
                lines.append(f"*... 还有 {len(cat_violations) - display_count} 条未展示，请优化匹配规则后重新扫描*")
                lines.append(f"")

        # 修复优先级建议
        lines.append(f"---")
        lines.append(f"")
        lines.append(f"## 🎯 修复优先级建议")
        lines.append(f"")
        if report.critical_count > 0:
            lines.append(f"1. **立即修复** ({report.critical_count} 项 critical): 硬编码凭据、SQL注入等安全漏洞必须立即处理")
        if report.high_count > 0:
            lines.append(f"2. **本周修复** ({report.high_count} 项 high): 命令注入、空异常处理、层级穿透、循环依赖")
        if report.medium_count > 0:
            lines.append(f"3. **下个迭代** ({report.medium_count} 项 medium): 函数过长、参数过多、可变默认参数")
        if report.low_count > 0:
            lines.append(f"4. **技术债务** ({report.low_count} 项 low): 嵌套过深、裸线程等可逐步优化")

        lines.append(f"")
        lines.append(f"---")
        lines.append(f"*报告由 CodeRef-AI GovernanceAuditor v1.0 生成*")
        lines.append(f"")
        lines.append("> **LLM 复查提示**：此报告可能包含误报。审查每条结果后，调用 `coderef_cache_whitelist` 工具将误报自动加入白名单，然后重新扫描。")

        return "\n".join(lines)
