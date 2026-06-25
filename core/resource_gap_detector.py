# -*- coding: utf-8 -*-
"""
资源遗漏检测器 —— 检测项目中缺失或未正确连接的资源

检测维度：
1. 缺失的本地模块：import 语句引用的本地模块文件不存在
2. 失效的动态路径：sys.path.insert/append 指向的路径不存在
3. 动态导入风险：importlib.import_module、__import__、exec 等动态导入
4. 未使用的依赖：requirements.txt 中声明但代码中未实际 import 的包
5. 未引用的环境变量：.env 文件中定义但代码中未引用的变量

输出：Markdown 报告，包含资源遗漏总览、缺失模块清单、风险点列表、
未使用依赖（可清理的 requirements.txt 条目）、未引用环境变量。

与 CodeSimplifier / GovernanceAuditor / JunkDetector 的关系：
- CodeSimplifier 聚焦代码精简（YAGNI、死代码、过度工程）
- GovernanceAuditor 聚焦安全与架构合规
- JunkDetector 聚焦项目中的垃圾文件清理
- ResourceGapDetector 聚焦资源遗漏（缺失的模块、未使用的依赖、环境变量遗漏）

作者: PersuadeAI Team
版本: v1.0
"""

import os
import re
import ast
from datetime import datetime
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict

from loguru import logger
from core.shared_filter import SharedFilter

_sf = SharedFilter()


# ═══════════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════════

@dataclass
class ResourceGap:
    """
    单条资源遗漏记录

    Attributes:
        category: 分类（missing_module / invalid_path / dynamic_import /
                  unused_dep / unreferenced_env）
        item: 资源项名称（如模块名、路径、依赖包名、环境变量名）
        detail: 详细说明
        file_path: 相关文件路径
        severity: 严重程度（high / medium / low）
        suggestion: 修复建议
    """
    category: str
    item: str
    detail: str
    file_path: str
    severity: str = "medium"
    suggestion: str = ""

    def to_dict(self) -> Dict:
        return {
            "category": self.category,
            "item": self.item,
            "detail": self.detail,
            "file_path": self.file_path,
            "severity": self.severity,
            "suggestion": self.suggestion,
        }


# ═══════════════════════════════════════════════════════════════════
# 分类标签与说明
# ═══════════════════════════════════════════════════════════════════

CATEGORY_LABELS = {
    "missing_module": "缺失的本地模块",
    "invalid_path": "失效的动态路径",
    "dynamic_import": "动态导入风险点",
    "unused_dep": "未使用的依赖",
    "unreferenced_env": "未引用的环境变量",
}

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}

# Python 标准库模块名（Python 3.10+ 常用）
STDLIB_MODULES = {
    "abc", "aifc", "argparse", "array", "ast", "asynchat", "asyncio",
    "asyncore", "atexit", "audioop", "base64", "bdb", "binascii", "binhex",
    "bisect", "builtins", "bz2", "calendar", "cgi", "cgitb", "chunk", "cmath",
    "cmd", "code", "codecs", "codeop", "collections", "colorsys", "compileall",
    "concurrent", "configparser", "contextlib", "contextvars", "copy", "copyreg",
    "cProfile", "crypt", "csv", "ctypes", "curses", "dataclasses", "datetime",
    "dbm", "decimal", "difflib", "dis", "distutils", "doctest", "email",
    "encodings", "enum", "errno", "faulthandler", "fcntl", "filecmp",
    "fileinput", "fnmatch", "formatter", "fractions", "ftplib", "functools",
    "gc", "getopt", "getpass", "gettext", "glob", "graphlib", "grp", "gzip",
    "hashlib", "heapq", "hmac", "html", "http", "idlelib", "imaplib", "imghdr",
    "imp", "importlib", "inspect", "io", "ipaddress", "itertools", "json",
    "keyword", "lib2to3", "linecache", "locale", "logging", "lzma", "mailbox",
    "mailcap", "marshal", "math", "mimetypes", "mmap", "modulefinder",
    "multiprocessing", "netrc", "nis", "nntplib", "numbers", "operator", "optparse",
    "os", "ossaudiodev", "pathlib", "pdb", "pickle", "pickletools", "pipes",
    "pkgutil", "platform", "plistlib", "poplib", "posix", "posixpath", "pprint",
    "profile", "pstats", "pty", "pwd", "py_compile", "pyclbr", "pydoc",
    "queue", "quopri", "random", "re", "readline", "reprlib", "resource",
    "rlcompleter", "runpy", "sched", "secrets", "select", "selectors",
    "shelve", "shlex", "shutil", "signal", "site", "smtpd", "smtplib",
    "sndhdr", "socket", "socketserver", "sqlite3", "ssl", "stat", "statistics",
    "string", "stringprep", "struct", "subprocess", "sunau", "symtable", "sys",
    "sysconfig", "syslog", "tabnanny", "tarfile", "telnetlib", "tempfile",
    "termios", "test", "textwrap", "threading", "time", "timeit", "tkinter",
    "token", "tokenize", "trace", "traceback", "tracemalloc", "tty", "turtle",
    "turtledemo", "types", "typing", "unicodedata", "unittest", "urllib",
    "uu", "uuid", "venv", "warnings", "wave", "weakref", "webbrowser",
    "winreg", "winsound", "wsgiref", "xdrlib", "xml", "xmlrpc", "zipapp",
    "zipfile", "zipimport", "zlib", "zoneinfo",
    # 常用第三方但被忽略的模式（不是标准库但常见）
}


# ═══════════════════════════════════════════════════════════════════
# 资源遗漏检测器
# ═══════════════════════════════════════════════════════════════════

class ResourceGapDetector:
    """
    资源遗漏检测器

    扫描项目目录，检测 5 类资源遗漏问题，生成 Markdown 报告。
    帮助发现"用户不知道、AI 没看到"的有价值资源或缺失的连接。

    用法:
        detector = ResourceGapDetector()
        report = detector.detect("/path/to/project")
        print(report)
    """

    # 扫描时忽略的目录名
    IGNORE_DIRS = {
        ".git", ".svn", ".hg",
        "__pycache__", ".pytest_cache", ".mypy_cache",
        ".ruff_cache", ".tox",
        "node_modules",
        ".venv", "venv", "env",
        "dist", "build", "egg-info",
    }

    def __init__(self):
        self._gaps: List[ResourceGap] = []
        self._all_py_files: List[str] = []
        self._all_imports: Set[str] = set()
        self._all_imports_by_file: Dict[str, Set[str]] = defaultdict(set)

    def detect(self, project_path: str) -> str:
        """
        执行资源遗漏检测并生成报告

        Args:
            project_path: 项目根目录路径

        Returns:
            Markdown 格式的资源遗漏报告
        """
        logger.info(f"[ResourceGapDetector] 开始扫描: {project_path}")

        # 加载项目专属的 cache 硬编码优化（白名单）
        SharedFilter.load_cache(project_path)

        from core.project_scope import ProjectScope
        self._scope = ProjectScope(project_path)
        self._scope.analyze()

        self._gaps = []

        # 收集所有 .py 文件
        self._all_py_files = self._collect_py_files(project_path)

        # 预收集所有 import 信息（多项检测共用）
        self._collect_all_imports(project_path)

        # 1. 检测缺失的本地模块
        self._check_missing_modules(project_path)

        # 2. 检测失效的 sys.path 路径
        self._check_sys_path(project_path)

        # 3. 检测动态导入风险
        self._check_dynamic_imports(project_path)

        # 4. 检测未使用的依赖
        self._check_unused_deps(project_path)

        # 5. 检测未引用的环境变量
        self._check_unreferenced_env(project_path)

        logger.info(f"[ResourceGapDetector] 扫描完成: 发现 {len(self._gaps)} 个资源遗漏项")

        return self._generate_report(project_path)

    # ─── 辅助：收集文件 ─────────────────────────────────────────────

    def _collect_py_files(self, project_path: str) -> List[str]:
        """收集所有 .py 文件路径"""
        py_files = []
        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if self._scope.should_scan(os.path.join(root, d))]
            for f in files:
                if f.endswith(".py"):
                    py_files.append(os.path.join(root, f))
        return py_files

    def _collect_all_imports(self, project_path: str):
        """预收集所有文件中的 import 信息"""
        import_pattern = re.compile(
            r'^\s*(?:from\s+([\w.]+)\s+import\s+\S|import\s+([\w.,\s]+?)(?:\s*(?:as|#|$)))',
            re.MULTILINE
        )

        for fpath in self._all_py_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue

            imports = set()
            for m in import_pattern.finditer(content):
                module = m.group(1) or m.group(2)
                if module:
                    # 处理 import a, b, c 的形式
                    for part in module.split(","):
                        part = part.strip().split(" as ")[0].strip()
                        if part:
                            imports.add(part)
                            self._all_imports.add(part)
            self._all_imports_by_file[fpath] = imports

    # ─── 检测 1: 缺失的本地模块 ─────────────────────────────────────

    def _check_missing_modules(self, project_path: str):
        """
        检查 import 语句中引用的本地模块是否存在

        判断逻辑：
        1. 提取所有 import 的模块名
        2. 排除标准库模块
        3. 排除已在 requirements.txt 中的第三方模块
        4. 检查本地是否有对应的 .py 文件或包目录
        5. 如果都没有，标记为缺失
        """
        # 获取 requirements.txt 中的包名
        req_packages = self._parse_requirements(project_path)

        # 构建本地模块映射：模块名 -> 文件路径
        local_modules: Dict[str, str] = {}
        for fpath in self._all_py_files:
            fname = os.path.basename(fpath)
            if fname == "__init__.py":
                # 包名是目录名
                pkg_name = os.path.basename(os.path.dirname(fpath))
                local_modules[pkg_name] = fpath
            else:
                module_name = fname[:-3]  # 去掉 .py
                local_modules[module_name] = fpath

        # 也检查子包：如 core.analyzer 对应 core/analyzer.py
        for fpath in self._all_py_files:
            rel = os.path.relpath(fpath, project_path).replace("\\", "/")
            if rel.endswith("/__init__.py"):
                # 包
                pkg_path = rel[:-12]  # 去掉 /__init__.py
                local_modules[pkg_path.replace("/", ".")] = fpath
            elif rel.endswith(".py"):
                mod_path = rel[:-3]  # 去掉 .py
                local_modules[mod_path.replace("/", ".")] = fpath

        # 检查每个 import
        checked_imports = set()
        for fpath, imports in self._all_imports_by_file.items():
            file_dir = os.path.dirname(fpath)
            for imp in imports:
                root_module = imp.split(".")[0]
                if root_module in checked_imports:
                    continue
                checked_imports.add(root_module)

                # 跳过标准库
                if root_module in STDLIB_MODULES:
                    continue
                # 跳过已在 requirements.txt 中的包（大小写不敏感）
                if root_module.lower() in req_packages:
                    continue
                # 跳过相对导入（以 . 开头）
                if imp.startswith("."):
                    continue
                # 跳过单字母模块名（正则误匹配，如 h、b）
                if len(root_module) <= 1:
                    continue
                # 跳过内置模块
                if root_module in ("__future__", "__main__"):
                    continue

                # 检查本地是否匹配
                found = False
                # 同目录匹配
                if root_module in local_modules:
                    found = True
                # 检查完整路径匹配
                elif imp in local_modules:
                    found = True
                else:
                    # 检查同目录下的 .py 文件
                    candidate = os.path.join(file_dir, root_module + ".py")
                    if os.path.isfile(candidate):
                        found = True
                    # 检查同目录下的包
                    candidate_dir = os.path.join(file_dir, root_module)
                    if os.path.isdir(candidate_dir) and os.path.isfile(
                            os.path.join(candidate_dir, "__init__.py")):
                        found = True

                if not found:
                    # 检查是否为条件导入（try-except ImportError）
                    if self._is_conditional_import(fpath, root_module):
                        continue
                    # 进一步确认：检查是否在 site-packages 中
                    if self._is_third_party_installed(root_module):
                        continue

                    self._gaps.append(ResourceGap(
                        category="missing_module",
                        item=imp,
                        detail=f"模块 `{imp}` 被 import，但在项目中找不到对应的文件，"
                               f"也不在标准库和 requirements.txt 中。",
                        file_path=fpath,
                        severity="high",
                        suggestion=f"检查模块 `{imp}` 是否缺失，或将其添加到 requirements.txt 中。",
                    ))

    def _is_conditional_import(self, filepath: str, module_name: str) -> bool:
        """检查 import 是否被 try-except ImportError 保护（条件导入）"""
        try:
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
        except (OSError, IOError):
            return False

        import ast as _ast
        try:
            tree = _ast.parse(content)
        except SyntaxError:
            return False

        # 遍历 AST，找到 import 语句，检查其父节点是否为 try-except
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] == module_name:
                        return self._is_in_try_except_import_error(node, tree)
            elif isinstance(node, _ast.ImportFrom):
                if node.module and node.module.split(".")[0] == module_name:
                    return self._is_in_try_except_import_error(node, tree)

        return False

    def _is_in_try_except_import_error(self, target_node, tree) -> bool:
        """检查节点是否在 try-except (ImportError | ModuleNotFoundError) 块中"""
        import ast as _ast
        for node in _ast.walk(tree):
            if isinstance(node, _ast.Try):
                # 检查 target_node 是否在 try 块中
                for child in _ast.walk(node):
                    if child is target_node:
                        # 检查 except handlers 是否捕获 ImportError/ModuleNotFoundError
                        for handler in node.handlers:
                            if handler.type:
                                if isinstance(handler.type, _ast.Tuple):
                                    for elt in handler.type.elts:
                                        if isinstance(elt, _ast.Name) and elt.id in ("ImportError", "ModuleNotFoundError"):
                                            return True
                                elif isinstance(handler.type, _ast.Name) and handler.type.id in ("ImportError", "ModuleNotFoundError"):
                                    return True
                        return False
        return False

    def _is_third_party_installed(self, module_name: str) -> bool:
        """检查第三方包是否已安装（通过尝试 import）"""
        try:
            # 使用 importlib.util.find_spec 来检查（不实际执行模块代码）
            from importlib.util import find_spec
            spec = find_spec(module_name)
            return spec is not None
        except (ImportError, ValueError, ModuleNotFoundError):
            return False

    # ─── 检测 2: 失效的 sys.path 路径 ───────────────────────────────

    def _check_sys_path(self, project_path: str):
        """
        检测 sys.path.insert / sys.path.append 指向的路径是否存在

        匹配模式：
        - sys.path.insert(0, "path")
        - sys.path.append("path")
        - sys.path.insert(0, os.path.join(os.path.dirname(__file__), "path"))
        """
        # 路径检测模式：只匹配直接的字符串字面量路径
        path_patterns = [
            # sys.path.insert(0, "xxx") 或 sys.path.append("xxx")
            re.compile(
                r'^\s*sys\.path\.(?:insert|append)\s*\(\s*\d*\s*,\s*["\']([^"\']+)["\']',
                re.IGNORECASE | re.MULTILINE
            ),
            # sys.path.insert(0, os.path.join(os.path.dirname(__file__), "xxx"))
            re.compile(
                r'^\s*sys\.path\.(?:insert|append)\s*\(\s*\d*\s*,\s*os\.path\.join\s*\(\s*'
                r'os\.path\.(?:dirname|abspath)\s*\(\s*__file__\s*\)\s*,\s*'
                r'["\']([^"\']+)["\']',
                re.IGNORECASE | re.MULTILINE
            ),
        ]

        for fpath in self._all_py_files:
            # 跳过自身文件（避免匹配文档字符串中的示例）
            if os.path.basename(fpath) == "resource_gap_detector.py":
                continue

            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue

            file_dir = os.path.dirname(fpath)

            for pattern in path_patterns:
                for m in pattern.finditer(content):
                    path_ref = m.group(1).strip().strip('"').strip("'")

                    # 跳过空字符串
                    if not path_ref:
                        continue

                    # 如果路径是相对路径，基于文件所在目录解析
                    if not os.path.isabs(path_ref):
                        resolved = os.path.join(file_dir, path_ref)
                    else:
                        resolved = path_ref

                    resolved = os.path.normpath(resolved)

                    if not os.path.exists(resolved):
                        lineno = content[:m.start()].count("\n") + 1
                        self._gaps.append(ResourceGap(
                            category="invalid_path",
                            item=path_ref,
                            detail=f"sys.path 指向的路径不存在: `{resolved}`",
                            file_path=f"{fpath}:{lineno}",
                            severity="high",
                            suggestion=f"检查路径 `{resolved}` 是否正确，或创建缺失的目录。",
                        ))

    # ─── 检测 3: 动态导入风险 ───────────────────────────────────────

    def _check_dynamic_imports(self, project_path: str):
        """
        检测动态导入语句，标记潜在风险

        检测模式：
        - importlib.import_module("...")
        - __import__("...")
        - exec(...)
        - eval(...)（包含字符串拼接的情况）
        """
        dynamic_patterns = [
            (re.compile(r'importlib\.import_module\s*\(', re.IGNORECASE),
             "importlib.import_module() 动态导入"),
            (re.compile(r'__import__\s*\(', re.IGNORECASE),
             "__import__() 动态导入"),
            (re.compile(r'\bexec\s*\(', re.IGNORECASE),
             "exec() 动态执行"),
            (re.compile(r'\beval\s*\(', re.IGNORECASE),
             "eval() 动态求值"),
            (re.compile(r'importlib\.util\.(?:find_spec|spec_from_file_location)\s*\(', re.IGNORECASE),
             "importlib.util 动态模块加载"),
        ]

        for fpath in self._all_py_files:
            # 跳过自身文件（避免报告自身文档和检测代码中的模式）
            if os.path.basename(fpath) == "resource_gap_detector.py":
                continue

            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue

            for pattern, desc in dynamic_patterns:
                for m in pattern.finditer(content):
                    lineno = content[:m.start()].count("\n") + 1
                    # 获取上下文行
                    lines = content.split("\n")
                    ctx_line = lines[lineno - 1].strip() if lineno <= len(lines) else ""

                    # 跳过注释行
                    if ctx_line.startswith("#"):
                        continue

                    # 跳过规则定义字符串中的代码模式（如 "eval() 会将字符串..."）
                    if _sf.is_pattern_def_line(ctx_line):
                        continue

                    self._gaps.append(ResourceGap(
                        category="dynamic_import",
                        item=desc,
                        detail=f"使用了 {desc}，这可能导致静态分析无法追踪依赖关系。"
                               f"如果模块路径是动态拼接的，运行时可能出错。",
                        file_path=f"{fpath}:{lineno}",
                        severity="medium",
                        suggestion="如果可能，改用静态 import 语句。如果是必需的动态导入，"
                                   "确保有充分的错误处理和 fallback 机制。",
                    ))

    # ─── 检测 4: 未使用的依赖 ───────────────────────────────────────

    def _check_unused_deps(self, project_path: str):
        """
        检测 requirements.txt 中声明的依赖是否在代码中实际被使用

        反向检查：requirements.txt 中的包 -> 代码中是否 import
        """
        req_packages = self._parse_requirements(project_path)
        if not req_packages:
            return

        # 收集所有 import 的顶层模块名
        all_imported_modules: Set[str] = set()
        for imp in self._all_imports:
            all_imported_modules.add(imp.split(".")[0])

        # 常见包名与 import 名的映射（包名可能与 import 名不同）
        PACKAGE_IMPORT_MAP = {
            "scikit-learn": "sklearn",
            "opencv-python": "cv2",
            "opencv-python-headless": "cv2",
            "python-dateutil": "dateutil",
            "python-dotenv": "dotenv",
            "pyyaml": "yaml",
            "pillow": "PIL",
            "beautifulsoup4": "bs4",
            "pymongo": "pymongo",
            "mysql-connector-python": "mysql",
            "psycopg2-binary": "psycopg2",
            "psycopg2": "psycopg2",
            "azure-storage-blob": "azure",
            "google-cloud-storage": "google",
            "django": "django",
            "flask": "flask",
            "fastapi": "fastapi",
            "sqlalchemy": "sqlalchemy",
            "pydantic": "pydantic",
            "celery": "celery",
            "redis": "redis",
            "aiohttp": "aiohttp",
            "httpx": "httpx",
            "websocket-client": "websocket",
            "python-multipart": "multipart",
            "python-jose": "jose",
            "passlib": "passlib",
            "bcrypt": "bcrypt",
            "cryptography": "cryptography",
            "markdown": "markdown",
            "jinja2": "jinja2",
            "boto3": "boto3",
            "botocore": "botocore",
            "docker": "docker",
            "kubernetes": "kubernetes",
            "prometheus-client": "prometheus_client",
            "gunicorn": "gunicorn",
            "uvicorn": "uvicorn",
            "pydantic-settings": "pydantic_settings",
            "starlette": "starlette",
        }

        for pkg_name, pkg_version in req_packages.items():
            pkg_lower = pkg_name.lower().replace("-", "_")
            import_name = PACKAGE_IMPORT_MAP.get(pkg_name.lower(), pkg_lower)

            # 检查是否被 import
            is_used = False
            for imported in all_imported_modules:
                imported_lower = imported.lower()
                if imported_lower == pkg_lower or imported_lower == import_name.lower():
                    is_used = True
                    break
                # 模糊匹配：包名是 import 名的前缀
                if imported_lower.startswith(pkg_lower + ".") or pkg_lower.startswith(imported_lower):
                    is_used = True
                    break

            if not is_used:
                # 检查是否在 setup.py/pyproject.toml 中被引用（非 import 使用）
                if self._is_dep_used_in_config(project_path, pkg_name):
                    continue

                self._gaps.append(ResourceGap(
                    category="unused_dep",
                    item=pkg_name,
                    detail=f"`{pkg_name}` 在 requirements.txt 中声明，但在代码中未找到对应的 import 语句。",
                    file_path=os.path.join(project_path, "requirements.txt"),
                    severity="low",
                    suggestion=f"如果确认不再使用 `{pkg_name}`，可以从 requirements.txt 中移除。"
                               f"（注意：某些工具包如 pytest、black 等可能通过命令行使用，不需要 import）",
                ))

    def _is_dep_used_in_config(self, project_path: str, pkg_name: str) -> bool:
        """检查依赖是否在配置文件中被引用（如 setup.py 的 install_requires、pyproject.toml）"""
        config_files = ["setup.py", "pyproject.toml", "setup.cfg", "tox.ini", ".pre-commit-config.yaml"]
        for cf in config_files:
            cf_path = os.path.join(project_path, cf)
            if os.path.isfile(cf_path):
                try:
                    with open(cf_path, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                    if pkg_name.lower() in content.lower():
                        return True
                except Exception:
                    pass
        return False

    # ─── 检测 5: 未引用的环境变量 ───────────────────────────────────

    def _check_unreferenced_env(self, project_path: str):
        """
        检测 .env 文件中的环境变量是否在代码中被引用

        正向检查：.env 中定义的变量 -> 代码中是否使用 os.getenv/os.environ
        """
        # 查找 .env 文件（支持 .env, .env.local, .env.development 等）
        env_vars: Dict[str, str] = {}  # 变量名 -> 来源文件
        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if self._scope.should_scan(os.path.join(root, d))]
            for f in files:
                if f == ".env" or f.startswith(".env."):
                    fpath = os.path.join(root, f)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                            for line in fh:
                                stripped = line.strip()
                                # 跳过注释和空行
                                if not stripped or stripped.startswith("#"):
                                    continue
                                # 解析 KEY=VALUE 或 KEY="VALUE"
                                if "=" in stripped:
                                    key = stripped.split("=", 1)[0].strip()
                                    # 跳过 export 前缀
                                    if key.startswith("export "):
                                        key = key[7:].strip()
                                    if key and re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', key):
                                        env_vars[key] = fpath
                    except Exception:
                        continue

        if not env_vars:
            return

        # 收集所有代码中引用的环境变量
        referenced_vars: Set[str] = set()
        env_patterns = [
            re.compile(r'os\.(?:environ|getenv)\s*\[\s*["\']([A-Za-z_][A-Za-z0-9_]*)["\']', re.IGNORECASE),
            re.compile(r'os\.(?:environ|getenv)\s*\(\s*["\']([A-Za-z_][A-Za-z0-9_]*)["\']', re.IGNORECASE),
            re.compile(r'os\.environ\.get\s*\(\s*["\']([A-Za-z_][A-Za-z0-9_]*)["\']', re.IGNORECASE),
            re.compile(r'process\.env\.([A-Za-z_][A-Za-z0-9_]*)', re.IGNORECASE),
            re.compile(r'\bconfig\s*\(\s*["\']([A-Za-z_][A-Za-z0-9_]*)["\']', re.IGNORECASE),
        ]

        for fpath in self._all_py_files:
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue

            for pattern in env_patterns:
                for m in pattern.finditer(content):
                    referenced_vars.add(m.group(1))

        # 也检查其他类型的文件（.js, .ts, .json, .yaml 等）
        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if self._scope.should_scan(os.path.join(root, d))]
            for f in files:
                ext = os.path.splitext(f)[1].lower()
                if ext not in (".js", ".ts", ".jsx", ".tsx", ".json", ".yaml", ".yml", ".toml", ".cfg"):
                    continue
                fpath = os.path.join(root, f)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                except Exception:
                    continue

                for var_name in env_vars:
                    if var_name in content:
                        referenced_vars.add(var_name)

        # 找出未引用的环境变量
        for var_name, env_file in env_vars.items():
            if var_name not in referenced_vars:
                self._gaps.append(ResourceGap(
                    category="unreferenced_env",
                    item=var_name,
                    detail=f"环境变量 `{var_name}` 在 `{os.path.relpath(env_file, project_path)}` "
                           f"中定义，但在代码中未找到引用。",
                    file_path=env_file,
                    severity="low",
                    suggestion=f"如果 `{var_name}` 确实不再使用，可以从 .env 文件中移除。"
                               f"如果仍在使用但未被检测到，请检查引用方式。",
                ))

    # ─── 辅助方法 ─────────────────────────────────────────────────

    def _parse_requirements(self, project_path: str) -> Dict[str, str]:
        """
        解析 requirements.txt 文件

        Returns:
            {包名: 版本号} 字典
        """
        req_path = os.path.join(project_path, "requirements.txt")
        if not os.path.isfile(req_path):
            return {}

        packages = {}
        try:
            with open(req_path, "r", encoding="utf-8", errors="ignore") as fh:
                for line in fh:
                    stripped = line.strip()
                    # 跳过注释、空行、-r 引用、--index-url、git+ 等
                    if not stripped or stripped.startswith("#"):
                        continue
                    if stripped.startswith("-r ") or stripped.startswith("--"):
                        continue
                    if stripped.startswith("git+") or stripped.startswith("http"):
                        continue
                    if stripped.startswith("-e "):
                        # 可编辑安装
                        continue

                    # 提取包名（去掉版本约束）
                    # 格式: package==1.0, package>=1.0, package~=1.0, package!=1.0
                    match = re.match(r'^([A-Za-z0-9][A-Za-z0-9._-]*)', stripped)
                    if match:
                        pkg_name = match.group(1).strip().lower()  # 统一小写
                        # 提取版本号
                        version_match = re.search(r'[=<>~!]+\s*([\d.]+)', stripped)
                        version = version_match.group(1) if version_match else ""
                        packages[pkg_name] = version

        except Exception as e:
            logger.warning(f"[ResourceGapDetector] 解析 requirements.txt 失败: {e}")

        return packages

    # ─── 报告生成 ─────────────────────────────────────────────────

    def _generate_report(self, project_path: str) -> str:
        """生成 Markdown 格式的资源遗漏报告"""
        lines = []

        # 分类统计
        cat_counts: Dict[str, int] = defaultdict(int)
        sev_counts: Dict[str, int] = defaultdict(int)
        for gap in self._gaps:
            cat_counts[gap.category] += 1
            sev_counts[gap.severity] += 1

        # 头部
        lines.append("# 资源遗漏检测报告")
        lines.append("")
        lines.append(f"> 项目: `{project_path}`")
        lines.append(f"> 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # 总览
        lines.append("## 资源遗漏总览")
        lines.append("")
        lines.append("| 指标 | 数值 |")
        lines.append("|------|------|")
        lines.append(f"| 发现问题数 | **{len(self._gaps)}** |")
        lines.append(f"| 高危 (high) | {sev_counts.get('high', 0)} |")
        lines.append(f"| 中危 (medium) | {sev_counts.get('medium', 0)} |")
        lines.append(f"| 低危 (low) | {sev_counts.get('low', 0)} |")
        lines.append("")

        if not self._gaps:
            lines.append("**未发现资源遗漏问题，项目资源连接状况良好。**")
            lines.append("")
            return "\n".join(lines)

        # 分类统计
        lines.append("### 按分类统计")
        lines.append("")
        lines.append("| 分类 | 数量 | 说明 |")
        lines.append("|------|------|------|")
        for cat in ["missing_module", "invalid_path", "dynamic_import", "unused_dep", "unreferenced_env"]:
            count = cat_counts.get(cat, 0)
            if count == 0:
                continue
            label = CATEGORY_LABELS.get(cat, cat)
            desc = {
                "missing_module": "代码中 import 了但项目里找不到的模块",
                "invalid_path": "sys.path 指向了不存在的路径",
                "dynamic_import": "使用了动态导入，可能隐藏依赖问题",
                "unused_dep": "requirements.txt 中声明但未使用的依赖",
                "unreferenced_env": ".env 中定义但代码中未引用的环境变量",
            }.get(cat, "")
            lines.append(f"| {label} | {count} | {desc} |")
        lines.append("")

        lines.append("---")
        lines.append("")

        # 分类详细清单（按严重程度排序）
        gaps_sorted = sorted(self._gaps, key=lambda g: (SEVERITY_ORDER.get(g.severity, 9), g.file_path))

        for cat in ["missing_module", "invalid_path", "dynamic_import", "unused_dep", "unreferenced_env"]:
            cat_gaps = [g for g in gaps_sorted if g.category == cat]
            if not cat_gaps:
                continue

            label = CATEGORY_LABELS.get(cat, cat)
            lines.append(f"## {label}（{len(cat_gaps)} 项）")
            lines.append("")

            for gap in cat_gaps:
                sev_tag = {"high": "[高危]", "medium": "[中危]", "low": "[低危]"}.get(gap.severity, "")
                lines.append(f"### {sev_tag} {gap.item}")
                lines.append("")
                lines.append(f"- **文件**: `{gap.file_path}`")
                lines.append(f"- **详情**: {gap.detail}")
                if gap.suggestion:
                    lines.append(f"- **建议**: {gap.suggestion}")
                lines.append("")

        lines.append("---")
        lines.append("")

        # 修复优先级建议
        lines.append("## 修复优先级建议")
        lines.append("")
        if sev_counts.get("high", 0) > 0:
            lines.append(f"1. **立即修复** ({sev_counts['high']} 项高危): 缺失的本地模块和失效的路径会导致程序运行失败")
        if sev_counts.get("medium", 0) > 0:
            lines.append(f"2. **尽快处理** ({sev_counts['medium']} 项中危): 动态导入风险需要评估，确保有充分的错误处理")
        if sev_counts.get("low", 0) > 0:
            lines.append(f"3. **定期清理** ({sev_counts['low']} 项低危): 未使用的依赖和环境变量可逐步清理")
        lines.append("")

        lines.append("---")
        lines.append("")
        lines.append(f"*报告由 CodeRef-AI ResourceGapDetector v1.0 生成*")

        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════
# 独立运行入口
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("用法: python resource_gap_detector.py <项目路径>")
        print("示例: python resource_gap_detector.py /path/to/project")
        sys.exit(1)

    target_path = sys.argv[1]
    if not os.path.isdir(target_path):
        print(f"错误: 路径不存在或不是目录: {target_path}")
        sys.exit(1)

    detector = ResourceGapDetector()
    report = detector.detect(target_path)
    print(report)
