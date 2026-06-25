# -*- coding: utf-8 -*-
"""
盲区检测器 —— 检测 AI、用户、代码之间的三方知识盲区

场景：用户不懂代码，AI 不知道用户不知道什么，AI 也不知道自己不知道什么。
本模块从多个维度扫描项目，找出"应该知道但不知道"的信息盲区。

检测维度：
1. 文档盲区：有代码但缺少文档的模块
2. 缺失依赖：import 了但目录中不存在的模块（可能是外部依赖或遗漏）
3. 动态路径注入：sys.path 动态修改，标记可能的外部依赖盲区
4. GitNexus 符号索引覆盖：哪些文件有符号但未被索引
5. 空文件：只有 import 没有实际代码的"占位"文件

与 CodeSimplifier / GovernanceAuditor 互补：
- CodeSimplifier 聚焦代码精简（YAGNI、死代码、过度工程）
- GovernanceAuditor 聚焦安全与架构合规（铁律、错题本）
- BlindSpotDetector 聚焦知识盲区（用户不知道、AI 不知道、代码缺失）

作者: PersuadeAI Team
版本: v1.0
"""

import os
import re
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass, field

from loguru import logger
from core.shared_filter import SharedFilter


# ═══════════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════════

@dataclass
class BlindSpot:
    """单条盲区检测结果

    Attributes:
        category: 分类（doc_blindspot / missing_dependency / dynamic_path /
                  unindexed_symbol / empty_file）
        item: 条目名称（模块名、文件名等）
        detail: 详细描述
        file_path: 关联文件路径
        risk_level: 风险等级（high / medium / low）
        user_should_know: 面向不懂代码的用户的解释
    """
    category: str
    item: str
    detail: str
    file_path: str
    risk_level: str
    user_should_know: str


RISK_ORDER = {"high": 0, "medium": 1, "low": 2}

CATEGORY_LABELS = {
    "doc_blindspot": "文档盲区",
    "missing_dependency": "缺失依赖",
    "dynamic_path": "动态路径注入",
    "unindexed_symbol": "符号索引盲区",
    "empty_file": "空文件",
}


# ═══════════════════════════════════════════════════════════════════
# 盲区检测器
# ═══════════════════════════════════════════════════════════════════

class BlindSpotDetector:
    """
    盲区检测器

    检测三方盲区（用户、AI、代码），帮助用户了解"自己不知道什么"和
    "AI 可能不知道什么"。
    """

    def __init__(self):
        self._all_py_files: List[str] = []
        self._all_imports: Dict[str, Set[str]] = {}  # file_path -> set of imports
        self._all_module_names: Set[str] = set()

    def detect(self, project_path: str) -> str:
        """
        执行盲区检测并生成报告

        Args:
            project_path: 项目路径

        Returns:
            Markdown 格式的盲区检测报告
        """
        logger.info(f"[BlindSpotDetector] 开始扫描: {project_path}")

        # 加载项目专属的 cache 硬编码优化（白名单）
        SharedFilter.load_cache(project_path)

        # 收集项目基础信息
        self._collect_project_info(project_path)

        spots: List[BlindSpot] = []

        # 1. 文档盲区
        spots.extend(self._detect_doc_blindspots(project_path))
        # 2. 缺失依赖
        spots.extend(self._detect_missing_dependencies(project_path))
        # 3. 动态路径注入
        spots.extend(self._detect_dynamic_paths(project_path))
        # 4. GitNexus 符号索引盲区（可选）
        spots.extend(self._detect_unindexed_symbols(project_path))
        # 5. 空文件
        spots.extend(self._detect_empty_files(project_path))

        # 按风险等级排序
        spots.sort(key=lambda s: (RISK_ORDER.get(s.risk_level, 9), s.item))

        logger.info(f"[BlindSpotDetector] 检测完成: {len(spots)} 个盲区")

        return self._generate_report(project_path, spots)

    # ─── 项目信息收集 ─────────────────────────────────────────────

    def _collect_project_info(self, project_path: str) -> None:
        """收集项目中所有 .py 文件和 import 信息"""
        from core.project_scope import ProjectScope

        self._all_py_files = []
        self._all_imports = {}
        self._all_module_names = set()

        scope = ProjectScope(project_path)
        scope.analyze()

        for root, dirs, files in os.walk(project_path):
            # 使用 ProjectScope 过滤目录
            dirs[:] = [d for d in dirs if scope.should_scan(os.path.join(root, d))]
            for f in files:
                if f.endswith(".py"):
                    fp = os.path.join(root, f)
                    self._all_py_files.append(fp)
                    rel = os.path.relpath(fp, project_path)
                    self._all_module_names.add(rel.replace(os.sep, ".").replace(".py", ""))

                    # 提取 import 语句
                    imports = self._extract_imports(fp)
                    self._all_imports[fp] = imports

        logger.info(f"[BlindSpotDetector] 收集到 {len(self._all_py_files)} 个 .py 文件")

    def _extract_imports(self, file_path: str) -> Set[str]:
        """从 .py 文件中提取所有 import 的模块名"""
        imports = set()
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
        except Exception:
            return imports

        for line in content.split("\n"):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            # from X.Y import Z
            m = re.match(r'from\s+([\w.]+)\s+import', stripped)
            if m:
                imports.add(m.group(1))
            # import X.Y
            m = re.match(r'import\s+([\w.]+)', stripped)
            if m:
                imports.add(m.group(1))
        return imports

    # ─── 检测规则 ─────────────────────────────────────────────────

    def _detect_doc_blindspots(self, project_path: str) -> List[BlindSpot]:
        """检测文档盲区：有 .py 文件的目录，但无对应 .md 文档"""
        spots = []

        # 收集有 .py 文件的目录（去重，取父目录层级）
        py_dirs = set()
        for fp in self._all_py_files:
            d = os.path.dirname(fp)
            py_dirs.add(d)

        # 检查 docs/ 目录
        docs_dir = os.path.join(project_path, "docs")
        if not os.path.isdir(docs_dir):
            # 整个项目没有 docs/ 目录
            for py_dir in sorted(py_dirs):
                rel = os.path.relpath(py_dir, project_path)
                py_count = sum(1 for fp in self._all_py_files
                               if os.path.dirname(fp) == py_dir)
                spots.append(BlindSpot(
                    category="doc_blindspot",
                    item=rel or "根目录",
                    detail=f"目录下有 {py_count} 个 Python 文件，但项目没有 docs/ 目录",
                    file_path=py_dir,
                    risk_level="high",
                    user_should_know=f"'{rel}' 目录里有 {py_count} 个代码文件，但没有任何文档说明它们是做什么的。你需要请开发者补充文档，否则你无法知道这些代码的功能和用法。",
                ))
            return spots

        # 收集 docs/ 下所有 .md 文件
        doc_files: Set[str] = set()
        for root, _, files in os.walk(docs_dir):
            for f in files:
                if f.endswith(".md"):
                    doc_files.add(os.path.splitext(f)[0].lower())

        # 按父目录分组 .py 文件
        dir_py_count: Dict[str, int] = defaultdict(int)
        for fp in self._all_py_files:
            d = os.path.dirname(fp)
            dir_py_count[d] += 1

        for py_dir, py_count in sorted(dir_py_count.items()):
            rel = os.path.relpath(py_dir, project_path)
            dir_name = os.path.basename(py_dir).lower()

            # 检查是否有对应的文档
            has_doc = False
            for doc_name in doc_files:
                if dir_name in doc_name or doc_name in dir_name:
                    has_doc = True
                    break

            if not has_doc and py_count >= 1:
                risk = "high" if py_count >= 5 else ("medium" if py_count >= 2 else "low")
                spots.append(BlindSpot(
                    category="doc_blindspot",
                    item=rel or "根目录",
                    detail=f"目录下有 {py_count} 个 Python 文件，但 docs/ 中无对应文档",
                    file_path=py_dir,
                    risk_level=risk,
                    user_should_know=f"'{rel}' 目录里有 {py_count} 个代码文件，但 docs/ 目录中没有对应的文档说明。这意味着没有人写过这些代码的功能说明，AI 也无法准确告诉你这些代码是做什么的。",
                ))

        logger.info(f"[BlindSpotDetector] 文档盲区: {len(spots)} 个")
        return spots

    def _detect_missing_dependencies(self, project_path: str) -> List[BlindSpot]:
        """检测缺失依赖：import 了但项目中不存在的模块"""
        spots = []

        # 收集所有标准库模块名（Python 3.10+）
        stdlib_modules = self._get_stdlib_modules()

        # 收集所有本地模块名
        local_modules = self._all_module_names.copy()

        all_imported: Set[str] = set()
        for imports in self._all_imports.values():
            all_imported.update(imports)

        # 检查每个 import 是否在本地或标准库中存在
        for imp in sorted(all_imported):
            # 跳过相对导入（以 . 开头，如 .auto_classifier）—— 相对导入始终是本地模块
            if imp.startswith("."):
                continue
            # 跳过标准库
            root = imp.split(".")[0]
            if root in stdlib_modules:
                continue
            # 跳过 Python 内置模块
            if root in ("__future__", "__main__"):
                continue
            # 跳过本地模块
            if imp in local_modules:
                continue
            # 检查顶级模块是否在本地
            if root in local_modules:
                continue

            # 找到引用该模块的文件
            ref_files = [fp for fp, imps in self._all_imports.items() if imp in imps]
            for ref_file in ref_files[:3]:  # 最多列 3 个引用
                spots.append(BlindSpot(
                    category="missing_dependency",
                    item=imp,
                    detail=f"import 了 '{imp}'，但项目中找不到该模块（可能是外部依赖，需要 pip install 检查）",
                    file_path=ref_file,
                    risk_level="high",
                    user_should_know=f"文件 '{os.path.basename(ref_file)}' 引用了一个叫 '{imp}' 的模块，但项目里找不到这个模块。这可能是需要额外安装的第三方库，或者是一个被删除/遗漏的模块。你需要确认环境是否完整。",
                ))

        logger.info(f"[BlindSpotDetector] 缺失依赖: {len(spots)} 个")
        return spots

    def _detect_dynamic_paths(self, project_path: str) -> List[BlindSpot]:
        """检测动态路径注入：sys.path.insert / sys.path.append"""
        spots = []
        pattern = re.compile(r'sys\.path\.(?:insert|append)\s*\(')

        for fp in self._all_py_files:
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except Exception:
                continue

            for i, line in enumerate(lines, 1):
                if pattern.search(line):
                    stripped = line.strip()
                    spots.append(BlindSpot(
                        category="dynamic_path",
                        item=f"sys.path 动态修改",
                        detail=f"第 {i} 行: {stripped[:100]}",
                        file_path=fp,
                        risk_level="medium",
                        user_should_know=f"代码在运行时动态修改了 Python 的模块搜索路径。这意味着有些模块的存放位置不在标准位置，可能导致 AI 分析时遗漏这些模块，或者在不同环境下运行报错。",
                    ))

        logger.info(f"[BlindSpotDetector] 动态路径注入: {len(spots)} 个")
        return spots

    def _detect_unindexed_symbols(self, project_path: str) -> List[BlindSpot]:
        """检测 GitNexus 符号索引盲区（可选）"""
        spots = []

        # 尝试导入 GitNexus 客户端
        try:
            from core.gitnexus_client import GitNexusClient
            client = GitNexusClient()
            indexed_files = client.get_indexed_files() if hasattr(client, "get_indexed_files") else set()
            if not indexed_files:
                logger.info("[BlindSpotDetector] GitNexus 索引为空，跳过符号索引盲区检测")
                return spots
        except Exception as e:
            logger.info(f"[BlindSpotDetector] GitNexus 不可用，跳过符号索引盲区: {e}")
            return spots

        # 检查哪些文件有符号定义但未被索引
        for fp in self._all_py_files:
            rel = os.path.relpath(fp, project_path)
            # 简单的符号检测：查找 def 和 class 定义
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    content = f.read()
            except Exception:
                continue

            has_symbols = bool(re.search(r'^\s*(def|class)\s+\w+', content, re.MULTILINE))
            if has_symbols and rel not in indexed_files and fp not in indexed_files:
                # 计数符号
                symbol_count = len(re.findall(r'^\s*(def|class)\s+\w+', content, re.MULTILINE))
                spots.append(BlindSpot(
                    category="unindexed_symbol",
                    item=rel,
                    detail=f"文件包含 {symbol_count} 个函数/类定义，但未被 GitNexus 索引覆盖",
                    file_path=fp,
                    risk_level="medium",
                    user_should_know=f"'{rel}' 文件中有 {symbol_count} 个函数或类，但代码索引工具没有收录它们。这意味着 AI 搜索代码时可能找不到这些定义，给出的分析可能不完整。",
                ))

        logger.info(f"[BlindSpotDetector] 符号索引盲区: {len(spots)} 个")
        return spots

    def _detect_empty_files(self, project_path: str) -> List[BlindSpot]:
        """检测空文件：只有 import 没有实际代码"""
        spots = []

        for fp in self._all_py_files:
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except Exception:
                continue

            if not lines:
                continue

            # 去除空行、注释、docstring、import 行
            meaningful_lines = []
            in_docstring = False
            for line in lines:
                stripped = line.strip()
                if not stripped:
                    continue
                if stripped.startswith("#"):
                    continue
                if stripped.startswith("import ") or stripped.startswith("from "):
                    continue
                if stripped in ("__all__",):
                    continue
                # 处理 docstring
                if stripped.startswith('"""') or stripped.startswith("'''"):
                    if in_docstring:
                        in_docstring = False
                        continue
                    elif stripped.endswith('"""') or stripped.endswith("'''"):
                        continue
                    else:
                        in_docstring = True
                        continue
                if in_docstring:
                    continue
                meaningful_lines.append(stripped)

            if not meaningful_lines:
                # 跳过 __init__.py —— 它们是正常的 Python 包标记文件
                fname = os.path.basename(fp)
                if fname == "__init__.py":
                    continue
                spots.append(BlindSpot(
                    category="empty_file",
                    item=os.path.relpath(fp, project_path),
                    detail=f"文件只有 import 和注释，没有实际代码逻辑（{len(lines)} 行）",
                    file_path=fp,
                    risk_level="low",
                    user_should_know=f"文件只包含 import 导入语句，没有实际的功能代码。这可能是一个空的占位文件，或者代码被删除了但文件忘了删除。你可以忽略它，但如果它被其他文件引用，可能会出问题。",
                ))

        logger.info(f"[BlindSpotDetector] 空文件: {len(spots)} 个")
        return spots

    # ─── 辅助方法 ─────────────────────────────────────────────────

    @staticmethod
    def _get_stdlib_modules() -> Set[str]:
        """获取 Python 3.10+ 标准库模块名集合"""
        stdlib = {
            "abc", "aifc", "argparse", "array", "ast", "asynchat", "asyncio",
            "asyncore", "atexit", "audioop", "base64", "bdb", "binascii", "binhex",
            "bisect", "builtins", "bz2", "calendar", "cgi", "cgitb", "chunk",
            "cmath", "cmd", "code", "codecs", "codeop", "collections", "colorsys",
            "compileall", "concurrent", "configparser", "contextlib", "contextvars",
            "copy", "copyreg", "cProfile", "crypt", "csv", "ctypes", "curses",
            "dataclasses", "datetime", "dbm", "decimal", "difflib", "dis",
            "distutils", "doctest", "email", "encodings", "enum", "errno",
            "faulthandler", "fcntl", "filecmp", "fileinput", "fnmatch", "fractions",
            "ftplib", "functools", "gc", "getopt", "getpass", "gettext", "glob",
            "graphlib", "grp", "gzip", "hashlib", "heapq", "hmac", "html", "http",
            "idlelib", "imaplib", "imghdr", "imp", "importlib", "inspect", "io",
            "ipaddress", "itertools", "json", "keyword", "lib2to3", "linecache",
            "locale", "logging", "lzma", "mailbox", "mailcap", "marshal", "math",
            "mimetypes", "mmap", "modulefinder", "multiprocessing", "netrc", "nis",
            "nntplib", "numbers", "operator", "optparse", "os", "ossaudiodev",
            "pathlib", "pdb", "pickle", "pickletools", "pipes", "pkgutil",
            "platform", "plistlib", "poplib", "posix", "posixpath", "pprint",
            "profile", "pstats", "pty", "pwd", "py_compile", "pyclbr", "pydoc",
            "queue", "quopri", "random", "re", "readline", "reprlib", "resource",
            "rlcompleter", "runpy", "sched", "secrets", "select", "selectors",
            "shelve", "shlex", "shutil", "signal", "site", "smtpd", "smtplib",
            "sndhdr", "socket", "socketserver", "sqlite3", "ssl", "stat",
            "statistics", "string", "stringprep", "struct", "subprocess", "sunau",
            "symtable", "sys", "sysconfig", "syslog", "tabnanny", "tarfile",
            "telnetlib", "tempfile", "termios", "test", "textwrap", "threading",
            "time", "timeit", "tkinter", "token", "tokenize", "trace", "traceback",
            "tracemalloc", "tty", "turtle", "turtledemo", "types", "typing",
            "unicodedata", "unittest", "urllib", "uu", "uuid", "venv", "warnings",
            "wave", "weakref", "webbrowser", "winreg", "winsound", "wsgiref",
            "xdrlib", "xml", "xmlrpc", "zipapp", "zipfile", "zipimport", "zlib",
            "zoneinfo", "_thread",
        }
        return stdlib

    # ─── 报告生成 ─────────────────────────────────────────────────

    def _generate_report(self, project_path: str, spots: List[BlindSpot]) -> str:
        """生成 Markdown 格式的盲区检测报告"""
        # 分类统计
        cat_counts: Dict[str, int] = defaultdict(int)
        risk_counts: Dict[str, int] = defaultdict(int)
        for s in spots:
            cat_counts[s.category] += 1
            risk_counts[s.risk_level] += 1

        lines = []
        lines.append("# 盲区检测报告")
        lines.append("")
        lines.append(f"> 项目路径: `{project_path}`")
        lines.append(f"> 扫描文件数: {len(self._all_py_files)}")
        lines.append(f"> 发现盲区: {len(spots)} 个")
        lines.append("")
        lines.append("> 盲区 = 用户不知道 + AI 不知道 + 代码中缺失的信息。")
        lines.append('> 本报告帮助你了解项目的\u201c信息黑洞\u201d，减少意外。')
        lines.append("")
        lines.append("---")
        lines.append("")

        # 盲区总览
        lines.append("## 盲区总览")
        lines.append("")
        lines.append("### 按分类统计")
        lines.append("")
        lines.append("| 分类 | 数量 | 说明 |")
        lines.append("|------|------|------|")
        for cat, label in CATEGORY_LABELS.items():
            count = cat_counts.get(cat, 0)
            if count > 0:
                desc = {
                    "doc_blindspot": "有代码但缺少文档",
                    "missing_dependency": "引用了不存在的模块",
                    "dynamic_path": "运行时修改了模块搜索路径",
                    "unindexed_symbol": "代码未被索引工具收录",
                    "empty_file": "只有 import 没有实际代码",
                }.get(cat, "")
                lines.append(f"| {label} | {count} | {desc} |")
        lines.append("")

        lines.append("### 按风险等级统计")
        lines.append("")
        lines.append("| 风险等级 | 数量 |")
        lines.append("|---------|------|")
        for risk in ["high", "medium", "low"]:
            count = risk_counts.get(risk, 0)
            if count > 0:
                label = {"high": "高", "medium": "中", "low": "低"}[risk]
                lines.append(f"| {label} | {count} |")
        lines.append("")

        if not spots:
            lines.append("本次扫描未发现盲区，项目信息结构良好。")
            return "\n".join(lines)

        lines.append("---")
        lines.append("")

        # 按分类展示详情
        for cat, label in CATEGORY_LABELS.items():
            cat_spots = [s for s in spots if s.category == cat]
            if not cat_spots:
                continue

            lines.append(f"## {label}（{len(cat_spots)} 个）")
            lines.append("")

            for s in cat_spots:
                risk_icon = {"high": "!!", "medium": "~", "low": "-"}[s.risk_level]
                lines.append(f"### [{risk_icon}] {s.item}")
                lines.append("")
                lines.append(f"- **文件**: `{s.file_path}`")
                lines.append(f"- **风险等级**: {s.risk_level}")
                lines.append(f"- **详情**: {s.detail}")
                lines.append(f"- **用户须知**: {s.user_should_know}")
                lines.append("")

        lines.append("---")
        lines.append("")

        # 建议
        lines.append("## 建议")
        lines.append("")
        lines.append("1. **文档盲区**：请开发者补充对应模块的 README 或 API 文档")
        lines.append("2. **缺失依赖**：检查 `requirements.txt` 或 `pyproject.toml` 是否完整")
        lines.append("3. **动态路径注入**：评估是否可以将模块移到标准位置")
        lines.append("4. **符号索引盲区**：确保 GitNexus 索引覆盖所有代码文件")
        lines.append("5. **空文件**：确认是否需要保留，不需要的可以删除")
        lines.append("")
        lines.append("---")
        lines.append("*报告由 CodeRef-AI BlindSpotDetector v1.0 生成*")

        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════
# 独立运行入口
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    detector = BlindSpotDetector()
    report = detector.detect(target)
    print(report)
