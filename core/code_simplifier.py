# -*- coding: utf-8 -*-
"""
代码精简建议器 — 借鉴 Ponytail 的懒人决策阶梯

Ponytail 核心理念（40K+ stars, 2026-06-12）：
  在写每一行代码之前，先走 5 级决策阶梯：
    1. 这东西真的需要存在吗？→ YAGNI
    2. 标准库能不能搞定？→ 用标准库
    3. 平台原生功能行不行？→ 用原生
    4. 已安装的依赖能用吗？→ 用已有依赖
    5. 一行能写完吗？→ 一行搞定
  只有到第 5 级还不满足，才写最少能跑的代码。

本模块将 Ponytail 的理念从「写代码时约束」扩展为「对已有代码做精简审计」，
结合 CodeRef_AI 的 CodeAnalyzer 数据模型，产出结构化的精简建议报告。

核心能力：
- 基于静态分析检测过度工程（YAGNI 违规、冗余抽象、重复实现）
- 基于依赖分析检测可替代的标准库/已有依赖
- 基于代码度量检测过长函数/过大类/死代码
- LLM 辅助判断：对不确定的项做语义级精简建议
- 产出 Markdown 报告，按优先级排序

用法：
    from core.code_simplifier import CodeSimplifier

    simplifier = CodeSimplifier()
    report = simplifier.analyze(project_path)
    # 或通过 MCP 工具 coderef_simplify_project 调用

作者: PersuadeAI Team
版本: v1.0
"""

import os
import re
import json
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict

from loguru import logger
from core.shared_filter import SharedFilter


# ═══════════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════════

@dataclass
class SimplificationItem:
    """
    单条精简建议

    Attributes:
        category: 分类（yagni/redundant_abstract/stdlib_replace/dead_code/
                   over_engineered/dependency_bloat/large_function/large_class）
        severity: 严重程度（critical/high/medium/low）
        file_path: 文件路径
        line_range: 行号范围 (start, end)
        title: 建议标题
        current: 当前代码描述
        suggestion: 精简建议
        savings: 预估节省行数
        risk: 风险等级（safe/moderate/risky）
        ponytail_rung: 对应 Ponytail 阶梯的第几级
    """
    category: str
    severity: str
    file_path: str
    line_range: Tuple[int, int]
    title: str
    current: str
    suggestion: str
    savings: int = 0
    risk: str = "safe"
    ponytail_rung: int = 0

    def to_dict(self) -> Dict:
        return {
            "category": self.category,
            "severity": self.severity,
            "file_path": self.file_path,
            "line_range": list(self.line_range),
            "title": self.title,
            "current": self.current,
            "suggestion": self.suggestion,
            "savings": self.savings,
            "risk": self.risk,
            "ponytail_rung": self.ponytail_rung,
        }


@dataclass
class SimplificationReport:
    """
    精简建议报告

    Attributes:
        project_path: 项目路径
        total_files: 扫描文件数
        total_lines: 总行数
        items: 精简建议列表
        total_savings: 总预估节省行数
        savings_percent: 节省百分比
        category_summary: 分类统计
        severity_summary: 严重程度统计
    """
    project_path: str
    total_files: int = 0
    total_lines: int = 0
    items: List[SimplificationItem] = field(default_factory=list)
    total_savings: int = 0
    savings_percent: float = 0.0
    category_summary: Dict[str, int] = field(default_factory=dict)
    severity_summary: Dict[str, int] = field(default_factory=dict)

    def compute_summary(self):
        """计算汇总统计"""
        self.total_savings = sum(i.savings for i in self.items)
        # 节省比例上限 100%（不同类别可能重叠计算）
        self.savings_percent = min((self.total_savings / max(self.total_lines, 1)) * 100, 100.0)
        self.category_summary = defaultdict(int)
        self.severity_summary = defaultdict(int)
        for item in self.items:
            self.category_summary[item.category] += 1
            self.severity_summary[item.severity] += 1


# ═══════════════════════════════════════════════════════════════════
# Ponytail 阶梯常量
# ═══════════════════════════════════════════════════════════════════

PONYTAIL_RUNGS = {
    1: "YAGNI — 这东西真的需要存在吗？",
    2: "标准库 — 标准库能不能搞定？",
    3: "原生功能 — 平台原生功能行不行？",
    4: "已有依赖 — 已安装的依赖能用吗？",
    5: "一行搞定 — 一行能写完吗？",
    6: "最小实现 — 写最少能跑的代码",
}

CATEGORY_LABELS = {
    "yagni": "YAGNI 违规（不需要的代码）",
    "redundant_abstract": "冗余抽象（过度封装）",
    "stdlib_replace": "可用标准库替代",
    "dead_code": "死代码（未引用）",
    "over_engineered": "过度工程",
    "dependency_bloat": "依赖膨胀",
    "large_function": "过长函数",
    "large_class": "过大类",
    "duplicate_code": "重复代码",
    "config_hardcode": "硬编码配置",
}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


# ═══════════════════════════════════════════════════════════════════
# 标准库替代映射
# ═══════════════════════════════════════════════════════════════════

STDLIB_REPLACEMENTS = {
    # Python: 常见第三方库 → 标准库替代
    "datetime": [("dateutil", "datetime 模块已足够"), ("arrow", "datetime + strftime"), ("pendulum", "datetime 模块")],
    "json": [("orjson", "json 模块（性能差异可忽略时）"), ("ujson", "json 模块")],
    "collections": [("blinker", "不需要信号库时")],
    "functools": [("toolz", "functools.partial/reduce")],
    "pathlib": [("path.py", "pathlib.Path")],
    "typing": [("typing_extensions", "typing 模块（Python 3.10+）")],
    "logging": [("loguru", "logging 模块（如无格式化需求）")],
    "http.client": [("requests", "http.client/urllib（简单场景）")],
    "urllib.request": [("requests", "urllib.request（简单 GET）")],
    "tempfile": [("tempdir", "tempfile.mkdtemp")],
    "hashlib": [("passlib", "hashlib（简单哈希）")],
    "re": [("regex", "re 模块（无高级特性需求时）")],
    "unittest": [("pytest", "unittest 模块（无需插件时）")],
    "argparse": [("click", "argparse（简单 CLI）"), ("typer", "argparse")],
    "concurrent.futures": [("celery", "concurrent.futures（单机场景）")],
    "sqlite3": [("SQLAlchemy", "sqlite3（简单查询）")],
    "csv": [("pandas", "csv 模块（简单读写）")],
    "xml.etree": [("lxml", "xml.etree.ElementTree（无 XPath 需求时）")],
    "email": [("flanker", "email 模块（简单解析）")],
    "secrets": [("bcrypt", "secrets 模块（简单 token）")],
    "socket": [("websockets", "socket（简单 TCP）")],
    "subprocess": [("sh", "subprocess.run")],
    "dataclasses": [("pydantic", "dataclasses（无验证需求时）"), ("attrs", "dataclasses")],
    "enum": [("enum34", "enum 模块（Python 3.4+）")],
    "asyncio": [("trio", "asyncio（标准协程）"), ("gevent", "asyncio")],
}


# ═══════════════════════════════════════════════════════════════════
# 代码精简器
# ═══════════════════════════════════════════════════════════════════

class CodeSimplifier:
    """
    代码精简建议器

    借鉴 Ponytail 的 5 级懒人决策阶梯，对已有代码做精简审计。

    分析维度：
    1. YAGNI 检测：未使用的函数/类/导入
    2. 标准库替代：第三方依赖可被标准库替代
    3. 过度工程：不必要的抽象层、配置系统、中间件
    4. 代码度量：过长函数（>80行）、过大类（>500行）
    5. 死代码：注释掉的代码块、TODO/FIXME 积压
    6. 重复代码：相似函数/类
    7. 硬编码：应提取为配置的魔法数字/字符串
    """

    def __init__(self, llm_client=None):
        """
        Args:
            llm_client: LLMIntegration 实例（可选，用于语义级判断）
        """
        self.llm = llm_client
        self._import_cache: Dict[str, set] = {}

    def analyze(self, project_path: str) -> str:
        """
        分析项目并生成精简建议报告

        Args:
            project_path: 项目路径

        Returns:
            Markdown 格式的精简建议报告
        """
        from core.code_analyzer import CodeAnalyzer

        logger.info(f"[CodeSimplifier] 开始分析: {project_path}")

        # 加载项目专属的 cache 硬编码优化（白名单）
        SharedFilter.load_cache(project_path)

        # 1. 基础代码分析
        analyzer = CodeAnalyzer()
        analysis = analyzer.analyze_project(project_path)

        # 2. 收集所有精简建议
        items: List[SimplificationItem] = []

        items.extend(self._detect_dead_imports(analysis))
        items.extend(self._detect_dead_functions(analysis))
        items.extend(self._detect_dead_classes(analysis))
        items.extend(self._detect_large_functions(analysis))
        items.extend(self._detect_large_classes(analysis))
        items.extend(self._detect_stdlib_replacements(analysis))
        items.extend(self._detect_over_abstractions(analysis))
        items.extend(self._detect_commented_code(analysis))
        items.extend(self._detect_hardcoded_values(analysis))
        items.extend(self._detect_todo_fixme(analysis))
        items.extend(self._detect_redundant_wrappers(analysis))

        # 3. LLM 辅助判断（可选）
        if self.llm and len(items) > 20:
            items = self._llm_filter_items(items, analysis)

        # 4. 按严重程度排序
        items.sort(key=lambda x: (SEVERITY_ORDER.get(x.severity, 9), -x.savings))

        # 5. 构建报告
        report = SimplificationReport(
            project_path=project_path,
            total_files=analysis.total_files,
            total_lines=analysis.total_lines,
            items=items,
        )
        report.compute_summary()

        logger.info(f"[CodeSimplifier] 分析完成: {len(items)} 条建议, "
                     f"预估节省 {report.total_savings} 行 ({report.savings_percent:.1f}%)")

        self.last_items = [item.to_dict() for item in items]

        return self._generate_report(report)

    # ─── 检测规则 ─────────────────────────────────────────────────

    def _detect_dead_imports(self, analysis) -> List[SimplificationItem]:
        """检测未使用的导入"""
        items = []
        for cf in analysis.files:
            if not cf.imports:
                continue
            # 收集文件中实际使用的模块名
            used_names = set()
            raw = cf.raw_content or ""
            # 简单检测：导入名是否在代码中出现（排除导入行本身）
            import_lines = set()
            for line_no, line in enumerate(raw.split("\n"), 1):
                stripped = line.strip()
                if stripped.startswith("import ") or stripped.startswith("from "):
                    import_lines.add(line_no)

            for imp in cf.imports:
                # 提取模块的最后一部分
                imp_name = imp.split(".")[-1]
                # 检查是否在非导入行中使用（使用词边界匹配，避免子串误匹配）
                found = False
                for line_no, line in enumerate(raw.split("\n"), 1):
                    if line_no in import_lines:
                        continue
                    if re.search(rf'\b{re.escape(imp_name)}\b', line):
                        found = True
                        break
                if not found:
                    items.append(SimplificationItem(
                        category="dead_code",
                        severity="low",
                        file_path=cf.file_path,
                        line_range=(0, 0),
                        title=f"未使用的导入: {imp}",
                        current=f"import {imp}",
                        suggestion="删除此导入",
                        savings=1,
                        risk="safe",
                        ponytail_rung=1,
                    ))
        return items

    def _detect_dead_functions(self, analysis) -> List[SimplificationItem]:
        """检测未调用的函数（跨文件分析）"""
        from collections import Counter
        items = []
        # 收集所有函数调用（跨文件），使用 Counter 统计次数
        all_calls = Counter()
        for cf in analysis.files:
            if hasattr(cf, 'function_calls') and cf.function_calls:
                all_calls.update(cf.function_calls)

        # 辅助：从原始内容中提取函数调用（排除关键字和内置函数）
        call_pattern = re.compile(r'([a-z_][a-zA-Z0-9_]*)\s*\(', re.IGNORECASE)
        KEYWORD_BLACKLIST = {
            'if', 'for', 'while', 'with', 'return', 'print', 'def', 'class', 'import',
            'from', 'try', 'except', 'raise', 'assert', 'yield', 'lambda', 'not', 'and',
            'or', 'in', 'is', 'del', 'pass', 'break', 'continue', 'global', 'nonlocal',
            'elif', 'else', 'finally', 'as', 'True', 'False', 'None',
        }
        for cf in analysis.files:
            raw = cf.raw_content or ""
            for m in call_pattern.finditer(raw):
                name = m.group(1)
                if name not in KEYWORD_BLACKLIST:
                    all_calls[name] += 1

        for cf in analysis.files:
            for func in cf.functions:
                # 跳过 dunder 方法和 main
                if func.name.startswith("__") or func.name in ("main",):
                    continue
                # 跳过很短的函数（可能是回调/属性）
                func_lines = func.end_line - func.start_line + 1
                if func_lines < 2:
                    continue
                # 检查是否被调用（跨文件），需要至少 1 次调用
                call_count = all_calls.get(func.name, 0)
                if call_count == 0:
                    items.append(SimplificationItem(
                        category="dead_code",
                        severity="medium" if func_lines > 20 else "low",
                        file_path=cf.file_path,
                        line_range=(func.start_line, func.end_line),
                        title=f"未调用的函数: {func.name}()",
                        current=f"函数 {func.name}（{func_lines}行）未被任何地方调用",
                        suggestion="确认是否为公共 API，否则删除",
                        savings=func_lines,
                        risk="moderate",
                        ponytail_rung=1,
                    ))
        return items

    def _detect_dead_classes(self, analysis) -> List[SimplificationItem]:
        """检测未使用的类"""
        from collections import Counter
        items = []
        # 使用 Counter 统计每个大写名称出现的次数
        all_refs = Counter()
        for cf in analysis.files:
            raw = cf.raw_content or ""
            refs = re.findall(r'\b([A-Z][a-zA-Z0-9_]*)\b', raw)
            all_refs.update(refs)

        for cf in analysis.files:
            for cls in cf.classes:
                if cls.name.startswith("_") and not cls.name.startswith("__"):
                    continue
                # 检查是否被引用（排除定义行和继承行）
                ref_count = all_refs.get(cls.name, 0)
                # 需要至少 2 次引用（类定义本身至少出现 1 次）
                if ref_count <= 1:
                    cls_lines = cls.end_line - cls.start_line + 1
                    items.append(SimplificationItem(
                        category="dead_code",
                        severity="high" if cls_lines > 100 else "medium",
                        file_path=cf.file_path,
                        line_range=(cls.start_line, cls.end_line),
                        title=f"未使用的类: {cls.name}",
                        current=f"类 {cls.name}（{cls_lines}行）未被引用",
                        suggestion="确认是否为公共 API，否则删除",
                        savings=cls_lines,
                        risk="moderate",
                        ponytail_rung=1,
                    ))
        return items

    def _detect_large_functions(self, analysis) -> List[SimplificationItem]:
        """检测过长函数（>80行）"""
        items = []
        for cf in analysis.files:
            for func in cf.functions:
                func_lines = func.end_line - func.start_line + 1
                if func_lines > 80:
                    # 检查 cache 复杂度豁免列表
                    if SharedFilter.is_complexity_exempted(func.name, cf.file_path):
                        continue
                    severity = "critical" if func_lines > 200 else ("high" if func_lines > 120 else "medium")
                    items.append(SimplificationItem(
                        category="large_function",
                        severity=severity,
                        file_path=cf.file_path,
                        line_range=(func.start_line, func.end_line),
                        title=f"过长函数: {func.name}()（{func_lines}行）",
                        current=f"函数体 {func_lines} 行，超出 Ponytail 推荐的 80 行上限",
                        suggestion="拆分为多个小函数，每个函数只做一件事",
                        savings=max(0, func_lines - 40),  # 预估拆分后节省
                        risk="moderate",
                        ponytail_rung=6,
                    ))
        return items

    def _detect_large_classes(self, analysis) -> List[SimplificationItem]:
        """检测过大类（>500行）"""
        items = []
        for cf in analysis.files:
            for cls in cf.classes:
                cls_lines = cls.end_line - cls.start_line + 1
                if cls_lines > 500:
                    severity = "critical" if cls_lines > 1000 else ("high" if cls_lines > 800 else "medium")
                    items.append(SimplificationItem(
                        category="large_class",
                        severity=severity,
                        file_path=cf.file_path,
                        line_range=(cls.start_line, cls.end_line),
                        title=f"过大类: {cls.name}（{cls_lines}行）",
                        current=f"类体 {cls_lines} 行，包含 {len(cls.methods)} 个方法",
                        suggestion="拆分为多个职责单一的类（SRP 原则）",
                        savings=max(0, cls_lines - 200),
                        risk="moderate",
                        ponytail_rung=6,
                    ))
        return items

    def _detect_stdlib_replacements(self, analysis) -> List[SimplificationItem]:
        """检测可用标准库替代的第三方依赖"""
        items = []
        all_imports = set()
        for cf in analysis.files:
            all_imports.update(cf.imports)

        for stdlib_mod, replacements in STDLIB_REPLACEMENTS.items():
            for third_party, reason in replacements:
                # 检查是否导入了第三方库
                tp_imported = any(third_party in imp for imp in all_imports)
                if tp_imported:
                    items.append(SimplificationItem(
                        category="stdlib_replace",
                        severity="medium",
                        file_path="项目级",
                        line_range=(0, 0),
                        title=f"可用标准库替代: {third_party} → {stdlib_mod}",
                        current=f"项目使用了 {third_party}",
                        suggestion=f"{reason}",
                        savings=0,  # 依赖减少不直接减少行数
                        risk="safe",
                        ponytail_rung=2,
                    ))
        return items

    def _detect_over_abstractions(self, analysis) -> List[SimplificationItem]:
        """检测过度抽象（只有一个实现的接口/基类/工厂）"""
        items = []
        for cf in analysis.files:
            for cls in cf.classes:
                # 检查只有一个子类的基类
                if len(cls.base_classes) == 0:
                    continue
                # 检查是否是抽象基类（名称含 Base/Abstract/Interface）
                name_lower = cls.name.lower()
                if any(kw in name_lower for kw in ["base", "abstract", "interface", "protocol"]):
                    cls_lines = cls.end_line - cls.start_line + 1
                    # 简单启发：如果基类只有 < 30 行，可能是过度抽象
                    if cls_lines < 30:
                        items.append(SimplificationItem(
                            category="redundant_abstract",
                            severity="low",
                            file_path=cf.file_path,
                            line_range=(cls.start_line, cls.end_line),
                            title=f"可能过度抽象: {cls.name}（{cls_lines}行）",
                            current=f"抽象基类/接口只有 {cls_lines} 行",
                            suggestion="如果只有一个实现，考虑合并基类和子类",
                            savings=cls_lines,
                            risk="moderate",
                            ponytail_rung=1,
                        ))
        return items

    def _detect_commented_code(self, analysis) -> List[SimplificationItem]:
        """检测注释掉的代码块"""
        items = []
        for cf in analysis.files:
            raw = cf.raw_content or ""
            lines = raw.split("\n")
            commented_blocks = []
            current_block_start = None
            current_block_count = 0

            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if stripped.startswith("#") and len(stripped) > 2:
                    # 检查是否是注释掉的代码（含 =, def, class, import, (, {, [）
                    code_indicators = ["def ", "class ", "import ", "from ", "=", "return ",
                                       "if ", "for ", "while ", "try:", "(", "{", "[", "->"]
                    if any(ind in stripped for ind in code_indicators):
                        if current_block_start is None:
                            current_block_start = i
                        current_block_count += 1
                    else:
                        if current_block_count >= 3:
                            commented_blocks.append((current_block_start, i - 1, current_block_count))
                        current_block_start = None
                        current_block_count = 0
                else:
                    if current_block_count >= 3:
                        commented_blocks.append((current_block_start, i - 1, current_block_count))
                    current_block_start = None
                    current_block_count = 0

            # 处理文件末尾的注释块
            if current_block_count >= 3 and current_block_start:
                commented_blocks.append((current_block_start, len(lines), current_block_count))

            for start, end, count in commented_blocks:
                items.append(SimplificationItem(
                    category="dead_code",
                    severity="low",
                    file_path=cf.file_path,
                    line_range=(start, end),
                    title=f"注释掉的代码块（{count}行）",
                    current=f"第 {start}-{end} 行有 {count} 行注释掉的代码",
                    suggestion="如果不再需要，直接删除（Git 保留了历史）",
                    savings=count,
                    risk="safe",
                    ponytail_rung=1,
                ))
        return items

    def _detect_hardcoded_values(self, analysis) -> List[SimplificationItem]:
        """检测硬编码的魔法数字和字符串"""
        items = []
        magic_number_pattern = re.compile(r'(?<![.\w])(\d{2,})(?![.\w])')
        config_patterns = [
            r'["\'](?:localhost|127\.0\.0\.1|0\.0\.0\.0)["\']',
            r'["\'](?:/tmp/|/var/|C:\\\\)["\']',
            r'["\'](?:admin|password|secret|token)["\'](?!\s*[:=])',
            r'["\'](?:http://|https://)[^"\']+["\']',
        ]

        for cf in analysis.files:
            if cf.language not in ("Python", "python"):
                continue
            raw = cf.raw_content or ""
            lines = raw.split("\n")

            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                # 跳过注释和字符串中的数字
                if stripped.startswith("#") or stripped.startswith("//"):
                    continue
                # 检查 URL 硬编码
                for pattern in config_patterns:
                    match = re.search(pattern, stripped)
                    if match:
                        matched_text = match.group()[:50]
                        # 检查 cache 白名单（用户标记为可接受的硬编码值）
                        if SharedFilter.is_magic_whitelisted(matched_text, cf.file_path):
                            continue
                        items.append(SimplificationItem(
                            category="config_hardcode",
                            severity="medium",
                            file_path=cf.file_path,
                            line_range=(i, i),
                            title=f"硬编码值: {match.group()[:50]}",
                            current=stripped[:80],
                            suggestion="提取到配置文件或环境变量",
                            savings=0,
                            risk="safe",
                            ponytail_rung=6,
                        ))
        return items

    def _detect_todo_fixme(self, analysis) -> List[SimplificationItem]:
        """检测 TODO/FIXME/HACK 积压"""
        items = []
        for cf in analysis.files:
            raw = cf.raw_content or ""
            lines = raw.split("\n")
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                for tag in ["TODO", "FIXME", "HACK", "XXX", "OPTIMIZE"]:
                    if tag in stripped and (stripped.startswith("#") or stripped.startswith("//")):
                        items.append(SimplificationItem(
                            category="dead_code",
                            severity="low",
                            file_path=cf.file_path,
                            line_range=(i, i),
                            title=f"{tag} 标记: {stripped[stripped.index(tag)+len(tag):].strip()[:60]}",
                            current=stripped[:80],
                            suggestion="处理或删除（超过 30 天的 TODO 通常不会被处理）",
                            savings=1,
                            risk="safe",
                            ponytail_rung=1,
                        ))
        return items

    def _detect_redundant_wrappers(self, analysis) -> List[SimplificationItem]:
        """检测冗余包装函数（只是转发调用，没有附加逻辑）"""
        items = []
        for cf in analysis.files:
            for func in cf.functions:
                code = func.code or ""
                # 检测简单的转发函数
                lines = [l.strip() for l in code.split("\n") if l.strip() and not l.strip().startswith("#")]
                if len(lines) <= 3:
                    # 检查是否只是 return other_func(...)
                    if lines and lines[-1].startswith("return ") and "(" in lines[-1]:
                        # 没有额外的处理逻辑
                        non_return_lines = [l for l in lines if not l.startswith("return")]
                        if not non_return_lines or all(l.startswith("def ") or l.startswith("\"\"\"") for l in non_return_lines):
                            func_lines = func.end_line - func.start_line + 1
                            items.append(SimplificationItem(
                                category="redundant_abstract",
                                severity="low",
                                file_path=cf.file_path,
                                line_range=(func.start_line, func.end_line),
                                title=f"冗余包装: {func.name}()",
                                current=f"函数只是转发调用，没有附加逻辑（{func_lines}行）",
                                suggestion="直接调用目标函数，删除包装层",
                                savings=func_lines,
                                risk="safe",
                                ponytail_rung=1,
                            ))
        return items

    # ─── LLM 辅助 ────────────────────────────────────────────────

    def _llm_filter_items(self, items: List[SimplificationItem], analysis) -> List[SimplificationItem]:
        """LLM 辅助过滤误报"""
        try:
            # 取 top 30 条给 LLM 判断
            top_items = items[:30]
            items_text = "\n".join([
                f"- [{i.category}] {i.file_path}:{i.line_range[0]} {i.title}"
                for i in top_items
            ])

            prompt = f"""以下是代码精简审计发现的 {len(items)} 条建议。
请判断哪些是真正的精简机会（保留），哪些是误报（标记为误报）。

项目: {analysis.project_path}
文件数: {analysis.total_files}
语言: {', '.join(analysis.languages.keys()) if analysis.languages else '未知'}

建议列表:
{items_text}

请以 JSON 数组格式返回，每个元素包含:
{{"index": 数字, "action": "keep"或"remove", "reason": "原因"}}

只返回 JSON 数组。"""

            raw = self.llm.chat([{"role": "user", "content": prompt}], max_tokens=2000)
            # 解析 LLM 响应
            json_match = re.search(r'\[.*\]', raw, re.DOTALL)
            if json_match:
                decisions = json.loads(json_match.group())
                remove_indices = {d["index"] for d in decisions if d.get("action") == "remove"}
                items = [i for idx, i in enumerate(top_items) if idx not in remove_indices] + items[30:]
                logger.info(f"[CodeSimplifier] LLM 过滤: 移除 {len(remove_indices)} 条误报")
        except Exception as e:
            logger.warning(f"[CodeSimplifier] LLM 过滤失败: {e}")
        return items

    # ─── 报告生成 ────────────────────────────────────────────────

    def _generate_report(self, report: SimplificationReport) -> str:
        """生成 Markdown 格式的精简建议报告"""
        lines = []

        # 头部
        lines.append("# 代码精简建议报告（Ponytail 风格）")
        lines.append("")
        lines.append(f"> 项目: `{report.project_path}`")
        lines.append(f"> 扫描文件数: {report.total_files} | 总行数: {report.total_lines:,}")
        lines.append(f"> 发现问题: {len(report.items)} 条")
        lines.append(f"> 预估可精简: **{report.total_savings:,} 行 ({report.savings_percent:.1f}%)**")
        lines.append(f"> 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        lines.append("")
        lines.append("> 本报告借鉴 [Ponytail](https://github.com/DietrichGebert/ponytail)（40K+ stars）的懒人决策阶梯，")
        lines.append("> 对已有代码做精简审计。每条建议标注了对应的 Ponytail 阶梯等级。")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Ponytail 阶梯说明
        lines.append("## Ponytail 懒人决策阶梯")
        lines.append("")
        for rung, desc in PONYTAIL_RUNGS.items():
            lines.append(f"{rung}. {desc}")
        lines.append("")
        lines.append("> 安全验证、错误处理、数据保护永远不会被建议精简。")
        lines.append("")
        lines.append("---")
        lines.append("")

        # 摘要统计
        lines.append("## 摘要统计")
        lines.append("")

        # 按严重程度
        lines.append("### 按严重程度")
        lines.append("")
        lines.append("| 严重程度 | 数量 |")
        lines.append("|---------|------|")
        for sev in ["critical", "high", "medium", "low"]:
            count = report.severity_summary.get(sev, 0)
            if count > 0:
                label = {"critical": "严重", "high": "高", "medium": "中", "low": "低"}[sev]
                lines.append(f"| {label} | {count} |")
        lines.append("")

        # 按分类
        lines.append("### 按分类")
        lines.append("")
        lines.append("| 分类 | 数量 |")
        lines.append("|------|------|")
        for cat, count in sorted(report.category_summary.items(), key=lambda x: -x[1]):
            label = CATEGORY_LABELS.get(cat, cat)
            lines.append(f"| {label} | {count} |")
        lines.append("")
        lines.append("---")
        lines.append("")

        # 详细建议列表
        lines.append("## 精简建议详情")
        lines.append("")

        # 按分类分组
        grouped = defaultdict(list)
        for item in report.items:
            grouped[item.category].append(item)

        for cat, cat_items in grouped.items():
            cat_label = CATEGORY_LABELS.get(cat, cat)
            lines.append(f"### {cat_label}")
            lines.append("")

            for item in cat_items:
                sev_icon = {"critical": "!!", "high": "!", "medium": "~", "low": "-"}.get(item.severity, "?")
                risk_label = {"safe": "安全", "moderate": "需验证", "risky": "高风险"}.get(item.risk, item.risk)
                rung_desc = PONYTAIL_RUNGS.get(item.ponytail_rung, "")

                lines.append(f"**[{sev_icon}] {item.title}**")
                lines.append("")
                lines.append(f"- 文件: `{item.file_path}:{item.line_range[0]}-{item.line_range[1]}`")
                lines.append(f"- 风险: {risk_label} | Ponytail 阶梯: 第{item.ponytail_rung}级（{rung_desc}）")
                if item.savings > 0:
                    lines.append(f"- 预估节省: ~{item.savings} 行")
                lines.append(f"- 现状: {item.current}")
                lines.append(f"- 建议: {item.suggestion}")
                lines.append("")

        lines.append("---")
        lines.append("")

        # 实施建议
        lines.append("## 实施建议")
        lines.append("")
        lines.append("1. **先处理 `safe` 风险的 `critical`/`high` 项** — 这些是低风险高收益的精简")
        lines.append("2. **再处理 `dead_code` 类** — 删除未使用的代码是最安全的精简")
        lines.append("3. **然后处理 `stdlib_replace`** — 减少依赖意味着减少维护负担")
        lines.append("4. **最后处理 `large_function`/`large_class`** — 拆分需要更多测试验证")
        lines.append("")
        lines.append("> 每次精简后运行测试套件，确保行为不变。")
        lines.append("> 建议分批提交，每批一个分类，便于回滚。")
        lines.append("")

        return "\n".join(lines)
