# -*- coding: utf-8 -*-
"""
技术债务检测器 —— 自动识别代码中的技术债务

检测维度：
1. TODO/FIXME/HACK/XXX/BUG 注释：扫描未完成的标记，按优先级排序
2. 圈复杂度检测：if/for/while 嵌套超过阈值的函数
3. 过长函数：超过 100 行的函数需要拆分
4. 嵌套过深：缩进超过 4 层的代码可读性差
5. 魔法数字/字符串：硬编码的 IP、端口、路径等应提取为配置
6. 注释掉的代码块：连续 3 行以上被注释的代码应清理

面向不懂代码的用户，每类债务都会附带通俗解释。

与 CodeSimplifier 和 GovernanceAuditor 互补：
- CodeSimplifier 聚焦代码精简（YAGNI、死代码、过度工程）
- GovernanceAuditor 聚焦安全与架构合规（铁律、错题本）
- TechDebtDetector 聚焦技术债务（未完成工作、代码质量下降）

作者: PersuadeAI Team
版本: v1.0
"""

import os
import re
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

from loguru import logger
from core.shared_filter import SharedFilter

_sf = SharedFilter()


# ═══════════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════════

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# TODO 标签优先级：数字越小越严重
TAG_PRIORITY = {
    "BUG": 0,
    "FIXME": 1,
    "HACK": 2,
    "TODO": 3,
    "XXX": 4,
}

CATEGORY_LABELS = {
    "todo_comment": "未完成标记（TODO/FIXME/HACK/BUG）",
    "high_complexity": "圈复杂度过高",
    "cognitive_complexity": "认知复杂度",
    "long_function": "过长函数",
    "deep_nesting": "嵌套过深",
    "magic_value": "魔法数字/硬编码",
    "commented_code": "被注释掉的代码",
    "comment_quality": "注释质量不足",
    "naming_convention": "命名规范问题",
}

SEVERITY_LABELS = {
    "critical": "严重",
    "high": "高",
    "medium": "中",
    "low": "低",
    "info": "提示",
}


@dataclass
class TechDebt:
    """
    单条技术债务

    Attributes:
        category: 分类（todo_comment / high_complexity / long_function /
                   deep_nesting / magic_value / commented_code）
        severity: 严重程度（critical / high / medium / low / info）
        file_path: 文件路径
        line: 行号
        description: 债务描述
        suggestion: 修复建议
        context: 上下文信息（所在函数/类名等）
        explanation: 对不懂代码的人的解释（LLM 生成或静态模板）
    """
    category: str
    severity: str
    file_path: str
    line: int
    description: str
    suggestion: str
    context: str = ""
    explanation: str = ""

    def to_dict(self) -> Dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "file_path": self.file_path,
            "line": self.line,
            "description": self.description,
            "suggestion": self.suggestion,
            "context": self.context,
            "explanation": self.explanation,
        }


# ═══════════════════════════════════════════════════════════════════
# 静态解释模板（LLM 不可用时使用）
# ═══════════════════════════════════════════════════════════════════

EXPLANATION_TEMPLATES = {
    "todo_comment": (
        "代码中留下了「待办事项」标记（如 TODO、FIXME），就像施工队留下的「此处未完」纸条。"
        "这些标记意味着功能还没有完全实现，或者有已知的 Bug 没有修复。"
        "如果长期不处理，这些标记会越积越多，最终没人记得它们当初是什么意思。"
    ),
    "high_complexity": (
        "这个函数的逻辑太复杂了，包含了许多 if/else 判断和循环嵌套，就像一团乱麻。"
        "复杂的代码难以理解和修改，很容易在改一个地方时不小心破坏另一个地方。"
        "建议将复杂的逻辑拆分成多个小函数，每个函数只做一件事。"
    ),
    "long_function": (
        "这个函数太长了，就像一个章节没有分段。"
        "长函数难以阅读和理解，一个新人可能需要花很长时间才能搞明白它做了什么。"
        "建议把长函数拆分成多个短函数，每个函数完成一个明确的子任务。"
    ),
    "deep_nesting": (
        "代码的缩进层次太深了，意味着「如果...那么...如果...那么...」的嵌套太多。"
        "深层嵌套就像俄罗斯套娃，让人很难追踪代码的执行路径。"
        "建议使用「提前返回」的方式减少嵌套，让代码更扁平。"
    ),
    "magic_value": (
        "代码中直接写入了具体的数字或字符串（如 IP 地址、端口号、文件路径），"
        "这些值被称为「魔法数字」，因为除了写代码的人，没人知道它们为什么是这个值。"
        "当环境变化时（如服务器地址变了），需要修改代码本身，而不是修改配置，容易出错。"
    ),
    "commented_code": (
        "代码中有大段被注释掉的旧代码，就像房间里堆着的旧家具。"
        "这些代码已经不使用了，但还留在文件里，占空间、让人困惑。"
        "Git 已经保存了历史版本，所以注释掉的代码可以安全删除。"
    ),
    "comment_quality": (
        "代码中缺少必要的注释，就像没有说明书的电器。"
        "公开函数和类如果没有 docstring，其他人（包括未来的自己）需要读完所有代码才能理解它的用途。"
        "好的注释不说「代码做了什么」（代码本身已经说明了），而是说「为什么这样做」和「怎么用」。"
    ),
    "naming_convention": (
        "变量和函数的命名不够规范，就像路牌用错了标识。"
        "Python 社区约定：变量和函数用 snake_case（小写_下划线），类用 PascalCase（大写开头），常量用 UPPER_CASE。"
        "不规范的命名会降低代码可读性，让协作变得困难。"
    ),
}


# ═══════════════════════════════════════════════════════════════════
# 技术债务检测器
# ═══════════════════════════════════════════════════════════════════

class TechDebtDetector:
    """
    技术债务检测器

    自动扫描代码库，识别 8 类技术债务：
    1. 未完成的 TODO/FIXME/HACK/BUG 注释
    2. 圈复杂度过高的函数
    3. 认知复杂度过高的函数
    4. 过长的函数
    5. 嵌套过深的代码
    6. 硬编码的魔法数字和字符串
    7. 被注释掉的代码块
    8. 注释质量不足（缺少 docstring 等）
    9. 命名规范问题（snake_case 等）

    所有检测基于正则/静态分析，不依赖 LLM。
    LLM 仅用于生成面向非技术用户的通俗解释。
    """

    # 阈值配置
    COMPLEXITY_THRESHOLD = 10       # 圈复杂度阈值（if/for/while/except 语句数）
    LONG_FUNCTION_THRESHOLD = 100   # 函数行数阈值
    NESTING_DEPTH_THRESHOLD = 4     # 嵌套深度阈值（缩进级别）
    COMMENTED_CODE_MIN_LINES = 3    # 注释代码块最少行数

    # TODO 标签正则
    TODO_TAG_PATTERN = re.compile(
        r'^\s*#\s*(TODO|FIXME|HACK|XXX|BUG)\b[:\s-]*(.*)',
        re.IGNORECASE,
    )

    # 魔法数字检测模式
    MAGIC_NUMBER_PATTERNS = [
        # IP 地址
        (re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'), "IP 地址", "medium"),
        # 端口号（常见端口范围）
        (re.compile(r'(?<![.\w])(?:port|PORT)\s*[:=]\s*(\d{2,5})(?![.\w])'), "端口号", "medium"),
        # 文件路径（Windows 和 Unix）
        (re.compile(r'["\'](?:[A-Za-z]:\\|/(?:home|tmp|var|etc|opt|usr)/)[^"\']+["\']'), "硬编码文件路径", "medium"),
        # URL（非 localhost）
        (re.compile(r'["\']https?://[^"\']+["\']'), "硬编码 URL", "medium"),
        # 超时/重试/阈值等魔法数字（排除 0, 1, 2 等常见小数字）
        (re.compile(r'(?<![.\w])(?:timeout|TIMEOUT|max_retries|MAX_RETRIES|threshold|THRESHOLD|limit|LIMIT)\s*[:=]\s*(\d{3,})(?![.\w])'), "硬编码阈值/限制", "low"),
        # 典型的魔法数字（排除 0, 1, 2, 10, 100 等常见值，排除赋值左边）
        (re.compile(r'(?<![.\w\d])(?!\d+\.\d+)(\d{3,})(?![.\w\d])'), "魔法数字", "low"),
    ]

    # 注释代码检测指示符
    COMMENTED_CODE_INDICATORS = [
        "def ", "class ", "import ", "from ", "return ",
        "if ", "for ", "while ", "try:", "except", "elif ", "else:",
        "=", "(", "{", "[", "->", "yield ", "raise ", "assert ",
        "with ", "async ", "await ", "print(", "len(", "range(",
    ]

    def __init__(self, llm_client=None):
        """
        Args:
            llm_client: LLMIntegration 实例（可选，用于生成通俗解释）
        """
        self.llm = llm_client

    def detect(self, project_path: str) -> str:
        """
        执行技术债务检测

        Args:
            project_path: 项目路径

        Returns:
            Markdown 格式的技术债务报告
        """
        from core.code_analyzer import CodeAnalyzer
        from core.project_scope import ProjectScope

        logger.info(f"[TechDebtDetector] 开始扫描: {project_path}")

        # 加载项目专属的 cache 硬编码优化（白名单）
        from core.shared_filter import SharedFilter
        SharedFilter.load_cache(project_path)

        # 使用 ProjectScope 建立项目边界
        scope = ProjectScope(project_path)
        scope.analyze()

        # 1. 基础代码分析（将 ProjectScope 的跳过目录注入 CodeAnalyzer）
        analyzer = CodeAnalyzer()
        # 扩展 CodeAnalyzer 的过滤规则，加入 ProjectScope 检测到的跳过目录
        original_should_ignore = analyzer._should_ignore
        skip_dirs = scope.get_skip_dirs()

        def _enhanced_should_ignore(path):
            if original_should_ignore(path):
                return True
            # 检查路径是否在 ProjectScope 的跳过目录中
            abs_path = str(path)
            for skip_dir in skip_dirs:
                if abs_path.startswith(skip_dir) or abs_path == skip_dir:
                    return True
            return False

        analyzer._should_ignore = _enhanced_should_ignore
        analysis = analyzer.analyze_project(project_path)

        # 2. 收集所有债务项
        debts: List[TechDebt] = []
        debts.extend(self._detect_todo_comments(analysis))
        debts.extend(self._detect_high_complexity(analysis))
        debts.extend(self._detect_cognitive_complexity(analysis))
        debts.extend(self._detect_long_functions(analysis))
        debts.extend(self._detect_deep_nesting(analysis))
        debts.extend(self._detect_magic_values(analysis))
        debts.extend(self._detect_commented_code(analysis))
        debts.extend(self._detect_comment_quality(analysis))
        debts.extend(self._detect_naming_convention(analysis))

        # 3. 按严重程度排序
        debts.sort(key=lambda d: (SEVERITY_ORDER.get(d.severity, 9), d.file_path, d.line))

        # 4. LLM 生成通俗解释（可选）
        if self.llm and debts:
            debts = self._generate_explanations(debts)

        # 5. 存储债务数据
        self.debts = debts

        # 6. 生成报告
        report = self._generate_report(debts, analysis)
        logger.info(f"[TechDebtDetector] 检测完成: {len(debts)} 条技术债务")

        return report

    # ─── 检测规则 ─────────────────────────────────────────────────

    def _detect_todo_comments(self, analysis) -> List[TechDebt]:
        """
        检测所有 .py 文件中的 TODO/FIXME/HACK/XXX/BUG 注释，
        提取所在函数/类上下文，按优先级排序。
        """
        debts = []

        for cf in analysis.files:
            if cf.language not in ("Python", "python"):
                continue
            raw = cf.raw_content or ""
            lines = raw.split("\n")

            # 构建函数/类的行号范围映射
            func_ranges = {}  # line -> func_name
            class_ranges = {}  # line -> class_name

            for func in cf.functions:
                for lineno in range(func.start_line, func.end_line + 1):
                    func_ranges[lineno] = func.name

            for cls in cf.classes:
                for lineno in range(cls.start_line, cls.end_line + 1):
                    class_ranges[lineno] = cls.name

            for i, line in enumerate(lines, 1):
                m = self.TODO_TAG_PATTERN.match(line)
                if not m:
                    continue

                tag = m.group(1).upper()
                message = m.group(2).strip() if m.group(2) else ""

                # 跳过检测器自身规则描述注释
                if _sf.is_comment_about_self(line):
                    continue
                # 跳过小写 xxx 占位符
                if tag == "XXX" and _sf.is_placeholder_xxx(line):
                    continue

                # 确定严重程度（基于标签优先级）
                if tag in ("BUG", "FIXME"):
                    severity = "high"
                elif tag == "HACK":
                    severity = "medium"
                elif tag == "TODO":
                    severity = "medium"
                else:
                    severity = "low"

                # 提取上下文
                context_parts = []
                class_name = class_ranges.get(i)
                func_name = func_ranges.get(i)
                if class_name:
                    context_parts.append(f"类 {class_name}")
                if func_name:
                    context_parts.append(f"函数 {func_name}()")
                context = " > ".join(context_parts) if context_parts else "模块顶层"

                description = f"[{tag}] {message}" if message else f"[{tag}] 未完成标记"
                suggestion = "尽快处理此标记，或在计划中记录处理时间"

                debts.append(TechDebt(
                    category="todo_comment",
                    severity=severity,
                    file_path=cf.file_path,
                    line=i,
                    description=description,
                    suggestion=suggestion,
                    context=context,
                    explanation=EXPLANATION_TEMPLATES["todo_comment"],
                ))

        return debts

    def _detect_high_complexity(self, analysis) -> List[TechDebt]:
        """
        检测圈复杂度高的函数。
        简单实现：统计函数体内 if/for/while/except/and/or 等分支语句的数量。
        """
        debts = []
        branch_pattern = re.compile(
            r'\b(if|elif|for|while|except)\b',
            re.IGNORECASE,
        )

        for cf in analysis.files:
            if cf.language not in ("Python", "python"):
                continue

            for func in cf.functions:
                code = func.code or ""
                if not code:
                    raw = cf.raw_content or ""
                    lines = raw.split("\n")
                    func_lines = lines[func.start_line - 1:func.end_line]
                    code = "\n".join(func_lines)

                # 统计分支语句数量
                branches = branch_pattern.findall(code)
                branch_count = len(branches)

                # 检查 cache 复杂度豁免列表
                if SharedFilter.is_complexity_exempted(func.name, cf.file_path):
                    continue

                if branch_count > self.COMPLEXITY_THRESHOLD:
                    func_lines_count = func.end_line - func.start_line + 1

                    if branch_count > 30:
                        severity = "critical"
                    elif branch_count > 20:
                        severity = "high"
                    elif branch_count > 15:
                        severity = "medium"
                    else:
                        severity = "low"

                    debts.append(TechDebt(
                        category="high_complexity",
                        severity=severity,
                        file_path=cf.file_path,
                        line=func.start_line,
                        description=f"函数 {func.name}() 圈复杂度为 {branch_count}（阈值 {self.COMPLEXITY_THRESHOLD}），"
                                    f"共 {func_lines_count} 行",
                        suggestion="将复杂逻辑拆分为多个小函数，使用策略模式或状态机简化分支",
                        context=f"函数 {func.name}()",
                        explanation=EXPLANATION_TEMPLATES["high_complexity"],
                    ))

        return debts

    def _detect_cognitive_complexity(self, analysis) -> List[TechDebt]:
        """检测认知复杂度（Cognitive Complexity）高的函数。
        认知复杂度不同于圈复杂度：它奖励嵌套+break重度打断控制流的结构。
        评分规则：if/elif/for/while/except +1分，嵌套（每层+1分），break/continue/return打断 +1分。
        """
        debts = []
        COG_THRESHOLD = 15  # SonarQube 默认阈值
        # 报告生成函数豁免（to_report / generate_*_report / fmt_*）
        # 这些函数的复杂性来自格式化逻辑，非业务逻辑
        REPORT_FUNC_PATTERN = re.compile(
            r'^(?:to_report|generate_.*report|fmt_.*|hz_bar|todo_sort_key)$', re.IGNORECASE
        )

        for cf in analysis.files:
            if cf.language not in ("Python", "python"):
                continue

            for func in cf.functions:
                # 豁免纯报告生成函数
                if REPORT_FUNC_PATTERN.match(func.name):
                    continue

                # 检查 cache 复杂度豁免列表
                if SharedFilter.is_complexity_exempted(func.name, cf.file_path):
                    continue

                code = func.code or ""
                if not code:
                    raw = cf.raw_content or ""
                    func_lines = raw.split("\n")[func.start_line - 1:func.end_line]
                    code = "\n".join(func_lines)

                if not code.strip():
                    continue

                score = self._compute_cognitive_complexity(code)
                if score >= COG_THRESHOLD:
                    severity = "high" if score >= 25 else "medium" if score >= 15 else "low"
                    debts.append(TechDebt(
                        category="cognitive_complexity",
                        severity=severity,
                        file_path=cf.file_path,
                        line=func.start_line,
                        description=f"函数 {func.name}() 认知复杂度为 {score}（阈值 {COG_THRESHOLD}），难以理解和维护",
                        suggestion="将嵌套逻辑提取为独立函数，减少打断控制流（break/continue/return），使用早返回简化逻辑",
                        context=f"函数 {func.name}()",
                        explanation='认知复杂度衡量代码"读起来有多难"。圈复杂度只统计分支数量，但认知复杂度还会惩罚嵌套和打断控制流（break/continue/return），因为它们会让代码更难理解。',
                    ))

        return debts

    def _compute_cognitive_complexity(self, code: str) -> int:
        """计算代码的认知复杂度（SonarQube 标准）"""
        score = 0
        nesting = 0
        i = 0
        lines = code.split("\n")
        tokens = []
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            tokens.extend(stripped.split())

        for j, tok in enumerate(tokens):
            # 结构增加嵌套
            if tok in ("if", "elif", "for", "while", "except", "with", "try"):
                nesting += 1
                score += 1
            # 嵌套惩罚
            elif tok in ("else",):
                score += 1  # else 增加认知负荷
            # 打断控制流
            elif tok in ("break", "continue"):
                if nesting > 0:
                    score += 1  # 打断嵌套结构
            # return 在非末尾
            elif tok == "return":
                if j < len(tokens) - 3:
                    score += 1  # 早返回打断控制流
            # 布尔运算符
            elif tok in ("and", "or"):
                if j > 0 and tokens[j - 1] not in ("if", "elif", "while", "for"):
                    score += 1  # 复杂布尔表达式

        return score

    def _detect_long_functions(self, analysis) -> List[TechDebt]:
        """检测过长的函数（>100 行）"""
        debts = []

        for cf in analysis.files:
            if cf.language not in ("Python", "python"):
                continue

            raw_lines = (cf.raw_content or "").split("\n")
            file_total_lines = len(raw_lines)

            for func in cf.functions:
                # 修正 end_line：CodeAnalyzer 对最后一个函数的 end_line 可能错误地
                # 设为文件总行数。通过检查函数代码内容或缩进回归来修正。
                end_line = func.end_line
                if end_line > file_total_lines:
                    end_line = file_total_lines

                # 进一步修正：如果 end_line 明显不合理（超过下一个函数/类的 start_line），
                # 则通过缩进回归找到函数体的真实结束行
                if func.start_line <= file_total_lines:
                    # 收集所有函数和类的起始行
                    boundary_lines = sorted(set(
                        [f.start_line for f in cf.functions if f is not func] +
                        [c.start_line for c in cf.classes]
                    ))
                    # 找到当前函数之后的第一个边界
                    next_boundary = None
                    for bl in boundary_lines:
                        if bl > func.start_line:
                            next_boundary = bl
                            break
                    if next_boundary and end_line >= next_boundary:
                        # 从 func.start_line 到 next_boundary-1 之间，
                        # 找到最后一个非空、非纯注释的行
                        for check_line in range(next_boundary - 1, func.start_line, -1):
                            if check_line <= file_total_lines:
                                line_text = raw_lines[check_line - 1].rstrip()
                                if line_text:  # 非空行
                                    end_line = check_line
                                    break

                func_lines = end_line - func.start_line + 1
                if func_lines > self.LONG_FUNCTION_THRESHOLD:
                    if func_lines > 300:
                        severity = "critical"
                    elif func_lines > 200:
                        severity = "high"
                    elif func_lines > 150:
                        severity = "medium"
                    else:
                        severity = "low"

                    debts.append(TechDebt(
                        category="long_function",
                        severity=severity,
                        file_path=cf.file_path,
                        line=func.start_line,
                        description=f"函数 {func.name}() 共 {func_lines} 行，"
                                    f"超过 {self.LONG_FUNCTION_THRESHOLD} 行阈值",
                        suggestion=f"将函数拆分为多个职责单一的小函数，每个不超过 {self.LONG_FUNCTION_THRESHOLD} 行",
                        context=f"函数 {func.name}()",
                        explanation=EXPLANATION_TEMPLATES["long_function"],
                    ))

        return debts

    def _detect_deep_nesting(self, analysis) -> List[TechDebt]:
        """
        检测嵌套过深的代码（>4 层缩进）。

        通过分析每行的前导空格数来判断嵌套深度。
        排除空行、注释行、续行和字符串。
        """
        debts = []

        for cf in analysis.files:
            if cf.language not in ("Python", "python"):
                continue
            raw = cf.raw_content or ""
            lines = raw.split("\n")

            for i, line in enumerate(lines, 1):
                stripped = line.rstrip()
                if not stripped:
                    continue
                if stripped.lstrip().startswith("#"):
                    continue

                # 计算缩进级别（以 4 空格为 1 级）
                indent = len(line) - len(stripped)
                indent_level = indent // 4

                if indent_level > self.NESTING_DEPTH_THRESHOLD:
                    # 排除续行（括号内换行、反斜杠续行等）
                    first_char = stripped[0] if stripped else ""
                    if first_char in (")", "}", "]", ".", ","):
                        continue

                    # 查找上下文
                    context = self._find_context_for_line(cf, i)

                    debts.append(TechDebt(
                        category="deep_nesting",
                        severity="low",
                        file_path=cf.file_path,
                        line=i,
                        description=f"嵌套深度 {indent_level} 层，"
                                    f"超过 {self.NESTING_DEPTH_THRESHOLD} 层阈值",
                        suggestion="使用 early return / guard clause 减少嵌套，或提取为子函数",
                        context=context,
                        explanation=EXPLANATION_TEMPLATES["deep_nesting"],
                    ))

                    # 只在每个文件中报告前 5 处过深嵌套，避免重复
                    if len([d for d in debts if d.file_path == cf.file_path and d.category == "deep_nesting"]) > 5:
                        # 移除最后添加的并跳出
                        debts.pop()
                        break

        return debts

    def _detect_magic_values(self, analysis) -> List[TechDebt]:
        """
        检测硬编码的魔法数字和字符串。
        包括 IP 地址、端口号、文件路径、URL 等。
        """
        debts = []
        seen = set()  # 去重：(file_path, line, pattern_type)

        for cf in analysis.files:
            if cf.language not in ("Python", "python"):
                continue
            raw = cf.raw_content or ""
            lines = raw.split("\n")

            in_docstring = False
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                # 跳过 import 行
                if stripped.startswith("import ") or stripped.startswith("from "):
                    continue
                # 跟踪多行 docstring 上下文
                if stripped.startswith('"""') or stripped.startswith("'''"):
                    in_docstring = not in_docstring
                    continue
                if in_docstring:
                    continue  # 多行 docstring 的内部行

                for pattern, label, severity in self.MAGIC_NUMBER_PATTERNS:
                    match = pattern.search(stripped)
                    if not match:
                        continue

                    matched_text = match.group(0) if match.lastindex is None else match.group(1)
                    matched_text = matched_text[:60]

                    key = (cf.file_path, i, label)
                    if key in seen:
                        continue
                    seen.add(key)

                    # 排除一些误报
                    if self._is_false_positive_magic(stripped, label, matched_text, cf.file_path):
                        continue

                    # 检查 cache 白名单（用户标记为可接受的硬编码值）
                    if SharedFilter.is_magic_whitelisted(matched_text, cf.file_path):
                        continue

                    context = self._find_context_for_line(cf, i)

                    debts.append(TechDebt(
                        category="magic_value",
                        severity=severity,
                        file_path=cf.file_path,
                        line=i,
                        description=f"硬编码 {label}: `{matched_text}`",
                        suggestion="提取到配置文件或环境变量中，便于不同环境切换",
                        context=context,
                        explanation=EXPLANATION_TEMPLATES["magic_value"],
                    ))

        return debts

    def _is_false_positive_magic(self, line: str, label: str, matched_text: str, file_path: str = "") -> bool:
        """判断魔法数字是否为误报"""
        # 排除版本号字符串
        if label == "魔法数字" and re.search(r'version|__version__|VERSION', line, re.IGNORECASE):
            return True
        # 排除注释中的 URL
        if label == "硬编码 URL" and line.strip().startswith("#"):
            return True
        # 排除 CWE 编号（如 CWE-798, CWE-502）
        if label == "魔法数字" and re.search(r'CWE[-\s]?\d+', line, re.IGNORECASE):
            return True
        # 排除 OWASP 年份编号（如 A07:2021）
        if label == "魔法数字" and re.search(r'A\d{2}:\d{4}', line):
            return True
        # 排除类常量/阈值变量赋值（如 THRESHOLD = 100, MAX_TOKENS = 4096）
        if label == "魔法数字" and re.search(
            r'(?:_THRESHOLD|_threshold|_LIMIT|_limit|_MAX|_max|_MIN|_min|_SIZE|_size)\s*[:=]\s*\d+',
            line, re.IGNORECASE
        ):
            return True
        # 排除 localhost
        if label == "IP 地址" and matched_text in ("127.0.0.1", "0.0.0.0"):
            return False  # localhost 也是硬编码，应该报告
        # 排除版本号如 3.14 等（被魔法数字误匹配）
        if label == "魔法数字" and re.match(r'^\d{3,}$', matched_text):
            if re.search(rf'\.{matched_text}\b', line):
                return True  # 看起来像版本号的小数部分

        # ─── 自动过滤：启发式规则减少误报 ───

        # 1. 常见小型常量（循环次数、分页大小、默认值、超时等）
        if label == "魔法数字" and matched_text.isdigit():
            n = int(matched_text)
            # 小于 100 的整数通常是循环次数、分页大小、默认值
            if n < 100:
                return True
            # 常见标准常量值
            if n in (100, 200, 201, 202, 204, 400, 401, 403, 404, 500, 502, 503):
                return True  # HTTP 状态码
            if n in (3600, 86400, 604800):
                return True  # 时间常量（小时、天、周）
            if n in (1024, 2048, 4096, 8192, 16384, 32768, 65536):
                return True  # 2的幂（内存/缓冲区大小）
            if n in (1000, 10000, 100000):
                return True  # 常见整十整百整千

        # 2. 0 和 1 是布尔值/索引/默认值
        if label == "魔法数字" and matched_text in ("0", "1"):
            return True

        # 3. 测试文件中的数字（测试数据）
        if "test" in os.path.basename(file_path).lower():
            return True

        # 4. 配置/常量文件中的数字
        cfg_fname = os.path.basename(file_path).lower()
        if any(kw in cfg_fname for kw in ("config", "settings", "constants", "const")):
            return True

        # 5. docstring 或注释中的数字
        if line.startswith("#") or line.startswith('"""') or line.startswith("'''"):
            return True

        return False

    def _detect_commented_code(self, analysis) -> List[TechDebt]:
        """
        检测被注释掉的代码块（连续 3 行以上被注释的代码）。
        """
        debts = []

        for cf in analysis.files:
            if cf.language not in ("Python", "python"):
                continue
            raw = cf.raw_content or ""
            lines = raw.split("\n")

            block_start = None
            block_lines = []

            for i, line in enumerate(lines, 1):
                stripped = line.strip()

                is_commented_code = False
                if stripped.startswith("#"):
                    after_hash = stripped[1:].strip()
                    if after_hash:
                        for indicator in self.COMMENTED_CODE_INDICATORS:
                            if after_hash.startswith(indicator):
                                is_commented_code = True
                                break

                if is_commented_code:
                    if block_start is None:
                        block_start = i
                    block_lines.append(stripped)
                else:
                    if block_start is not None and len(block_lines) >= self.COMMENTED_CODE_MIN_LINES:
                        debts.append(TechDebt(
                            category="commented_code",
                            severity="low",
                            file_path=cf.file_path,
                            line=block_start,
                            description=f"被注释掉的代码块，共 {len(block_lines)} 行 "
                                        f"（第 {block_start}-{i - 1} 行）",
                            suggestion="如果不再需要，直接删除；Git 历史已保留旧版本",
                            context=f"第 {block_start}-{i - 1} 行",
                            explanation=EXPLANATION_TEMPLATES["commented_code"],
                        ))
                    block_start = None
                    block_lines = []

            # 处理文件末尾的注释块
            if block_start is not None and len(block_lines) >= self.COMMENTED_CODE_MIN_LINES:
                debts.append(TechDebt(
                    category="commented_code",
                    severity="low",
                    file_path=cf.file_path,
                    line=block_start,
                    description=f"被注释掉的代码块，共 {len(block_lines)} 行 "
                                f"（第 {block_start}-{len(lines)} 行）",
                    suggestion="如果不再需要，直接删除；Git 历史已保留旧版本",
                    context=f"第 {block_start}-{len(lines)} 行",
                    explanation=EXPLANATION_TEMPLATES["commented_code"],
                ))

        return debts

    def _detect_comment_quality(self, analysis) -> List[TechDebt]:
        """检测注释质量问题：公开函数/类缺少 docstring，docstring 过短"""
        debts = []
        import ast

        for cf in analysis.files:
            if cf.language not in ("Python", "python"):
                continue
            if not cf.file_path.endswith(".py"):
                continue
            try:
                with open(cf.file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                tree = ast.parse(content)
            except (SyntaxError, OSError):
                continue

            for node in ast.iter_child_nodes(tree):
                # 检测公开类缺少 docstring
                if isinstance(node, ast.ClassDef):
                    if not node.name.startswith("_"):
                        doc = ast.get_docstring(node)
                        if not doc:
                            debts.append(TechDebt(
                                category="comment_quality",
                                severity="medium",
                                file_path=cf.file_path,
                                line=node.lineno,
                                description=f"公开类 {node.name} 缺少 docstring",
                                suggestion="为类添加简要说明，包括用途、使用示例",
                                context=f"类 {node.name}",
                                explanation=EXPLANATION_TEMPLATES["comment_quality"],
                            ))
                        elif len(doc.strip()) < 10:
                            debts.append(TechDebt(
                                category="comment_quality",
                                severity="low",
                                file_path=cf.file_path,
                                line=node.lineno,
                                description=f"类 {node.name} 的 docstring 过短（{len(doc.strip())} 字符）",
                                suggestion="补充更详细的说明，至少包含用途和使用方式",
                                context=f"类 {node.name}",
                                explanation=EXPLANATION_TEMPLATES["comment_quality"],
                            ))

                # 检测公开函数缺少 docstring
                elif isinstance(node, ast.FunctionDef):
                    if not node.name.startswith("_") or node.name == "__init__":
                        # 跳过简单的 getter/setter/property
                        if len(node.body) <= 2 and all(
                            isinstance(s, (ast.Return, ast.Assign, ast.Expr))
                            for s in node.body
                        ):
                            continue
                        doc = ast.get_docstring(node)
                        if not doc:
                            debts.append(TechDebt(
                                category="comment_quality",
                                severity="low",
                                file_path=cf.file_path,
                                line=node.lineno,
                                description=f"公开函数 {node.name}() 缺少 docstring",
                                suggestion="为函数添加简要说明，包括参数和返回值",
                                context=f"函数 {node.name}()",
                                explanation=EXPLANATION_TEMPLATES["comment_quality"],
                            ))

        return debts

    def _detect_naming_convention(self, analysis) -> List[TechDebt]:
        """检测命名规范问题：snake_case 违规、单字母变量、类名问题"""
        debts = []
        import ast

        # Python 保留字和常见合理缩写
        COMMON_SINGLE_OK = {"x", "y", "z", "i", "j", "k", "n", "m", "f", "s", "e", "a", "b", "c", "d", "t", "p", "q", "r", "v", "w", "h", "l", "_"}

        for cf in analysis.files:
            if cf.language not in ("Python", "python"):
                continue
            if not cf.file_path.endswith(".py"):
                continue
            try:
                with open(cf.file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                tree = ast.parse(content)
            except (SyntaxError, OSError):
                continue

            for node in ast.walk(tree):
                # 检测函数名：应该是 snake_case
                if isinstance(node, ast.FunctionDef):
                    if node.name.startswith("_"):
                        name = node.name.lstrip("_")
                    else:
                        name = node.name
                    # 跳过特殊方法（__xxx__）
                    if node.name.startswith("__") and node.name.endswith("__"):
                        continue
                    # 检测驼峰命名（类方法除外）
                    if re.search(r'[A-Z]', name) and not name.isupper():
                        debts.append(TechDebt(
                            category="naming_convention",
                            severity="low",
                            file_path=cf.file_path,
                            line=node.lineno,
                            description=f"函数 {node.name}() 使用了驼峰命名，不符合 Python snake_case 规范",
                            suggestion=f"重命名为 {re.sub(r'(?<!^)(?=[A-Z])', '_', name).lower()}",
                            context=f"函数 {node.name}()",
                            explanation=EXPLANATION_TEMPLATES["naming_convention"],
                        ))

                # 检测变量赋值中的单字母变量（排除常见循环变量）
                if isinstance(node, ast.Assign):
                    for target in node.targets:
                        if isinstance(target, ast.Name):
                            if len(target.id) == 1 and target.id not in COMMON_SINGLE_OK:
                                # 检查 cache 命名豁免
                                if SharedFilter.is_naming_exempted(target.id):
                                    continue
                                # 检查是否在循环/推导式中
                                debts.append(TechDebt(
                                    category="naming_convention",
                                    severity="info",
                                    file_path=cf.file_path,
                                    line=node.lineno,
                                    description=f"单字母变量 {target.id} 影响可读性",
                                    suggestion="使用有意义的变量名，例如用 result 代替 r，用 error 代替 e",
                                    context=f"变量 {target.id}",
                                    explanation=EXPLANATION_TEMPLATES["naming_convention"],
                                ))

                # 检测类名：应该是 PascalCase
                if isinstance(node, ast.ClassDef):
                    if not node.name[0].isupper() and not node.name.startswith("_"):
                        debts.append(TechDebt(
                            category="naming_convention",
                            severity="low",
                            file_path=cf.file_path,
                            line=node.lineno,
                            description=f"类名 {node.name} 应以大写字母开头（PascalCase）",
                            suggestion=f"重命名为 {node.name[0].upper() + node.name[1:]}",
                            context=f"类 {node.name}",
                            explanation=EXPLANATION_TEMPLATES["naming_convention"],
                        ))

        return debts

    # ─── 辅助方法 ─────────────────────────────────────────────────

    def _find_context_for_line(self, cf, line_number: int) -> str:
        """查找指定行所在的函数或类上下文"""
        context_parts = []
        for cls in cf.classes:
            if cls.start_line <= line_number <= cls.end_line:
                context_parts.append(f"类 {cls.name}")
                break
        for func in cf.functions:
            if func.start_line <= line_number <= func.end_line:
                context_parts.append(f"函数 {func.name}()")
                break
        return " > ".join(context_parts) if context_parts else "模块顶层"

    # ─── LLM 辅助 ────────────────────────────────────────────────

    def _generate_explanations(self, debts: List[TechDebt]) -> List[TechDebt]:
        """
        使用 LLM 为每类债务生成通俗解释。

        由于为每一条债务调用 LLM 成本太高，我们按类别批量生成解释，
        然后分配给该类别的所有债务项。
        """
        try:
            # 收集所有出现的类别
            categories = list(set(d.category for d in debts))

            for cat in categories:
                # 取该类别的几条代表性债务
                samples = [d for d in debts if d.category == cat][:3]
                samples_text = "\n".join([
                    f"- {d.description} (文件: {d.file_path}, 行: {d.line})"
                    for d in samples
                ])

                prompt = f"""你是一个代码质量助手，正在向不懂编程的业务人员解释技术债务。

以下是代码中发现的「{CATEGORY_LABELS.get(cat, cat)}」类问题的几个例子：

{samples_text}

请用通俗易懂的语言，解释：
1. 这类问题是什么（用比喻，不要用术语）
2. 为什么它会影响项目
3. 如果不处理会有什么后果

要求：
- 语言通俗，初中生能听懂
- 不超过 200 字
- 不要使用代码术语（如"函数"、"类"等，可以用"模块"、"功能块"代替）
- 全部用中文"""

                raw = self.llm.chat([{"role": "user", "content": prompt}], max_tokens=500)
                explanation = raw.strip()

                if explanation:
                    # 分配给该类别的所有债务
                    for d in debts:
                        if d.category == cat:
                            d.explanation = explanation

            logger.info(f"[TechDebtDetector] LLM 生成了 {len(categories)} 类解释")

        except Exception as e:
            logger.warning(f"[TechDebtDetector] LLM 解释生成失败: {e}，使用静态模板")

        return debts

    # ─── 报告生成 ────────────────────────────────────────────────

    def _generate_report(self, debts: List[TechDebt], analysis) -> str:
        """生成 Markdown 格式的技术债务报告"""
        lines = []

        # 统计
        cat_counts = defaultdict(int)
        sev_counts = defaultdict(int)
        for d in debts:
            cat_counts[d.category] += 1
            sev_counts[d.severity] += 1

        # 债务严重度评分
        score_penalty = (
            sev_counts.get("critical", 0) * 10 +
            sev_counts.get("high", 0) * 5 +
            sev_counts.get("medium", 0) * 2 +
            sev_counts.get("low", 0) * 0.5
        )
        max_penalty = max(analysis.total_files, 1) * 5
        debt_score = max(0, min(100, 100 - int(score_penalty / max(max_penalty, 1) * 100)))

        if debt_score >= 80:
            score_level = "良好"
        elif debt_score >= 50:
            score_level = "一般"
        else:
            score_level = "较差"

        # 头部
        lines.append("# 技术债务检测报告")
        lines.append("")
        lines.append(f"> 项目: `{analysis.project_path}`")
        lines.append(f"> 扫描文件数: {analysis.total_files} | 总行数: {analysis.total_lines:,}")
        lines.append(f"> 发现问题: {len(debts)} 条")
        lines.append(f"> 债务健康分: **{debt_score}/100** ({score_level})")
        lines.append(f"> 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # 总览
        lines.append("## 技术债务总览")
        lines.append("")

        lines.append("### 按严重程度分布")
        lines.append("")
        lines.append("| 严重程度 | 数量 | 说明 |")
        lines.append("|---------|------|------|")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = sev_counts.get(sev, 0)
            if count > 0:
                sev_desc = {
                    "critical": "必须立即处理",
                    "high": "应尽快处理",
                    "medium": "建议处理",
                    "low": "可逐步处理",
                    "info": "仅供参考",
                }
                lines.append(f"| {SEVERITY_LABELS[sev]} | {count} | {sev_desc.get(sev, '')} |")
        lines.append("")

        lines.append("### 按分类统计")
        lines.append("")
        lines.append("| 分类 | 数量 | 为什么重要 |")
        lines.append("|------|------|-----------|")
        for cat in ["todo_comment", "comment_quality", "high_complexity", "cognitive_complexity", "long_function", "deep_nesting", "magic_value", "commented_code", "naming_convention"]:
            count = cat_counts.get(cat, 0)
            if count > 0:
                importance = {
                    "todo_comment": "未完成的工作积累会拖慢项目进度",
                    "comment_quality": "缺少注释的代码难以理解和维护",
                    "high_complexity": "复杂代码容易产生 Bug，难以维护",
                    "cognitive_complexity": "认知复杂度高意味着代码读起来困难",
                    "long_function": "长函数难以理解和测试",
                    "deep_nesting": "深层嵌套降低代码可读性",
                    "magic_value": "硬编码值导致配置变更困难",
                    "commented_code": "废弃代码让文件混乱，误导开发者",
                    "naming_convention": "不规范的命名降低协作效率",
                }
                lines.append(f"| {CATEGORY_LABELS[cat]} | {count} | {importance.get(cat, '')} |")
        lines.append("")
        lines.append("---")
        lines.append("")

        if not debts:
            lines.append("**未发现技术债务，项目代码质量良好。**")
            return "\n".join(lines)

        # ─── 详细清单 ─────────────────────────────────────────────

        # 1. TODO/FIXME 清单（按优先级：FIXME/BUG > HACK > TODO > XXX）
        todo_debts = [d for d in debts if d.category == "todo_comment"]
        if todo_debts:
            # 按标签优先级排序
            def todo_sort_key(d):
                for tag, pri in TAG_PRIORITY.items():
                    if tag in d.description.upper():
                        return pri
                return 99

            todo_debts.sort(key=lambda d: (todo_sort_key(d), d.file_path, d.line))

            lines.append("## TODO/FIXME 清单")
            lines.append("")
            lines.append("> 以下按优先级排列：FIXME/BUG > HACK > TODO > XXX")
            lines.append("")
            lines.append("| 优先级 | 标记 | 文件 | 行号 | 内容 | 所在位置 |")
            lines.append("|--------|------|------|------|------|----------|")
            for d in todo_debts:
                tag = "?"
                for t in ["BUG", "FIXME", "HACK", "TODO", "XXX"]:
                    if t in d.description.upper():
                        tag = t
                        break
                file_short = os.path.basename(d.file_path)
                desc_short = d.description[:50] + "..." if len(d.description) > 50 else d.description
                lines.append(f"| {tag} | {SEVERITY_LABELS.get(d.severity, '')} | `{file_short}` | {d.line} | {desc_short} | {d.context} |")
            lines.append("")

            # 面向不懂代码的用户的解释
            lines.append("### 对非技术人员的解释")
            lines.append("")
            sample = todo_debts[0]
            lines.append(sample.explanation if sample.explanation else EXPLANATION_TEMPLATES["todo_comment"])
            lines.append("")
            lines.append("---")
            lines.append("")

        # 2. 复杂度高的函数列表
        complexity_debts = [d for d in debts if d.category == "high_complexity"]
        if complexity_debts:
            lines.append("## 圈复杂度过高的函数")
            lines.append("")
            lines.append("| 严重程度 | 文件 | 行号 | 函数 | 分支数 |")
            lines.append("|---------|------|------|------|--------|")
            for d in complexity_debts:
                file_short = os.path.basename(d.file_path)
                # 提取分支数
                branch_match = re.search(r'圈复杂度为 (\d+)', d.description)
                branch_count = branch_match.group(1) if branch_match else "?"
                func_name = d.context.replace("函数 ", "").replace("()", "")
                lines.append(f"| {SEVERITY_LABELS.get(d.severity, '')} | `{file_short}` | {d.line} | {func_name}() | {branch_count} |")
            lines.append("")

            lines.append("### 对非技术人员的解释")
            lines.append("")
            lines.append(complexity_debts[0].explanation if complexity_debts[0].explanation else EXPLANATION_TEMPLATES["high_complexity"])
            lines.append("")
            lines.append("---")
            lines.append("")

        # 3. 过长函数列表
        long_func_debts = [d for d in debts if d.category == "long_function"]
        if long_func_debts:
            lines.append("## 过长函数列表")
            lines.append("")
            lines.append("| 严重程度 | 文件 | 行号 | 函数 | 行数 |")
            lines.append("|---------|------|------|------|------|")
            for d in long_func_debts:
                file_short = os.path.basename(d.file_path)
                line_match = re.search(r'共 (\d+) 行', d.description)
                line_count = line_match.group(1) if line_match else "?"
                func_name = d.context.replace("函数 ", "").replace("()", "")
                lines.append(f"| {SEVERITY_LABELS.get(d.severity, '')} | `{file_short}` | {d.line} | {func_name}() | {line_count} |")
            lines.append("")

            lines.append("### 对非技术人员的解释")
            lines.append("")
            lines.append(long_func_debts[0].explanation if long_func_debts[0].explanation else EXPLANATION_TEMPLATES["long_function"])
            lines.append("")
            lines.append("---")
            lines.append("")

        # 4. 嵌套过深列表
        nesting_debts = [d for d in debts if d.category == "deep_nesting"]
        if nesting_debts:
            lines.append("## 嵌套过深列表")
            lines.append("")
            lines.append("| 文件 | 行号 | 嵌套深度 | 所在位置 |")
            lines.append("|------|------|----------|----------|")
            for d in nesting_debts:
                file_short = os.path.basename(d.file_path)
                depth_match = re.search(r'嵌套深度 (\d+) 层', d.description)
                depth = depth_match.group(1) if depth_match else "?"
                lines.append(f"| `{file_short}` | {d.line} | {depth} 层 | {d.context} |")
            lines.append("")

            lines.append("### 对非技术人员的解释")
            lines.append("")
            lines.append(nesting_debts[0].explanation if nesting_debts[0].explanation else EXPLANATION_TEMPLATES["deep_nesting"])
            lines.append("")
            lines.append("---")
            lines.append("")

        # 5. 魔法数字/字符串列表
        magic_debts = [d for d in debts if d.category == "magic_value"]
        if magic_debts:
            lines.append("## 魔法数字/硬编码列表")
            lines.append("")
            lines.append("| 严重程度 | 文件 | 行号 | 类型 | 值 | 所在位置 |")
            lines.append("|---------|------|------|------|-----|----------|")
            for d in magic_debts:
                file_short = os.path.basename(d.file_path)
                # 提取类型和值
                desc = d.description.replace("硬编码 ", "")
                lines.append(f"| {SEVERITY_LABELS.get(d.severity, '')} | `{file_short}` | {d.line} | {desc} | {d.context} |")
            lines.append("")

            lines.append("### 对非技术人员的解释")
            lines.append("")
            lines.append(magic_debts[0].explanation if magic_debts[0].explanation else EXPLANATION_TEMPLATES["magic_value"])
            lines.append("")
            lines.append("---")
            lines.append("")

        # 6. 被注释掉的代码块列表
        commented_debts = [d for d in debts if d.category == "commented_code"]
        if commented_debts:
            lines.append("## 被注释掉的代码块列表")
            lines.append("")
            lines.append("| 文件 | 行号 | 行数 | 位置 |")
            lines.append("|------|------|------|------|")
            for d in commented_debts:
                file_short = os.path.basename(d.file_path)
                line_match = re.search(r'共 (\d+) 行', d.description)
                line_count = line_match.group(1) if line_match else "?"
                lines.append(f"| `{file_short}` | {d.line} | {line_count} | {d.context} |")
            lines.append("")

            lines.append("### 对非技术人员的解释")
            lines.append("")
            lines.append(commented_debts[0].explanation if commented_debts[0].explanation else EXPLANATION_TEMPLATES["commented_code"])
            lines.append("")
            lines.append("---")
            lines.append("")

        # 7. 注释质量问题
        comment_quality_debts = [d for d in debts if d.category == "comment_quality"]
        if comment_quality_debts:
            lines.append("## 注释质量不足")
            lines.append("")
            lines.append("| 严重程度 | 文件 | 行号 | 问题 | 位置 |")
            lines.append("|---------|------|------|------|------|")
            for d in comment_quality_debts:
                file_short = os.path.basename(d.file_path)
                lines.append(f"| {SEVERITY_LABELS.get(d.severity, '')} | `{file_short}` | {d.line} | {d.description} | {d.context} |")
            lines.append("")
            lines.append("### 对非技术人员的解释")
            lines.append("")
            lines.append(comment_quality_debts[0].explanation if comment_quality_debts[0].explanation else EXPLANATION_TEMPLATES["comment_quality"])
            lines.append("")
            lines.append("---")
            lines.append("")

        # 8. 命名规范问题
        naming_debts = [d for d in debts if d.category == "naming_convention"]
        if naming_debts:
            lines.append("## 命名规范问题")
            lines.append("")
            lines.append("| 严重程度 | 文件 | 行号 | 问题 | 建议 |")
            lines.append("|---------|------|------|------|------|")
            for d in naming_debts:
                file_short = os.path.basename(d.file_path)
                lines.append(f"| {SEVERITY_LABELS.get(d.severity, '')} | `{file_short}` | {d.line} | {d.description} | {d.suggestion[:60]} |")
            lines.append("")
            lines.append("### 对非技术人员的解释")
            lines.append("")
            lines.append(naming_debts[0].explanation if naming_debts[0].explanation else EXPLANATION_TEMPLATES["naming_convention"])
            lines.append("")
            lines.append("---")
            lines.append("")

        # 修复建议
        lines.append("## 修复优先级建议")
        lines.append("")
        lines.append("| 优先级 | 债务类型 | 建议行动 |")
        lines.append("|--------|---------|----------|")
        lines.append("| 1（立即） | FIXME/BUG 标记 | 修复已知 Bug，消除安全隐患 |")
        lines.append("| 2（本周） | 圈复杂度过高 | 重构复杂函数，降低 Bug 风险 |")
        lines.append("| 3（本周） | 过长函数 | 拆分长函数，提高可测试性 |")
        lines.append("| 4（本月） | 魔法数字/硬编码 | 提取配置，支持不同环境部署 |")
        lines.append("| 5（本月） | 注释质量不足 | 补充公开接口的 docstring |")
        lines.append("| 6（本月） | TODO/HACK 标记 | 逐一处理或纳入迭代计划 |")
        lines.append("| 7（下月） | 嵌套过深 | 使用 early return 优化代码结构 |")
        lines.append("| 8（下月） | 命名规范问题 | 统一命名风格，提高可读性 |")
        lines.append("| 9（下月） | 注释掉的代码 | 清理废弃代码，保持代码库整洁 |")
        lines.append("")
        lines.append("> 建议每次迭代处理 1-2 类债务，逐步改善代码质量。")
        lines.append("> 不要试图一次性修复所有债务，那样容易引入新的 Bug。")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("*报告由 CodeRef-AI TechDebtDetector v1.0 生成*\n")
        lines.append("")
        lines.append("> **LLM 复查提示**：此报告可能包含误报。审查每条结果后，调用 `coderef_cache_whitelist` 工具将误报自动加入白名单，然后重新扫描。")

        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════
# 独立运行测试
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    # 确保项目根目录在 sys.path 中
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    # 默认测试路径：coderef-ai 项目自身
    test_path = project_root
    if len(sys.argv) > 1:
        test_path = sys.argv[1]

    print(f"TechDebtDetector 测试运行")
    print(f"扫描路径: {test_path}")
    print(f"=" * 60)

    detector = TechDebtDetector()
    report = detector.detect(test_path)

    # 输出到文件
    output_file = os.path.join(test_path, "tech_debt_report.md")
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(report)

    print(f"报告已保存到: {output_file}")
    print(f"报告长度: {len(report)} 字符")
