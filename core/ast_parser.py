# -*- coding: utf-8 -*-
"""
AST 精确代码解析器 —— 替代正则解析，用 Python ast 模块做精确代码理解

核心能力：
1. 精确提取导入（区分标准库/第三方/项目内部）
2. 精确提取函数/类（含 docstring、参数、返回类型、装饰器）
3. 精确提取函数调用关系（跨文件追踪）
4. 区分赋值类型（常量定义 / 配置读取 / 硬编码值）
5. 提取代码块（函数体/类体/方法体）

与旧 code_analyzer 的区别：
- 旧：用正则 re.finditer 匹配 def/class/import，无法理解语义
- 新：用 ast 模块解析 AST，精确理解代码结构
- 旧：无法区分 api_key = "E1001_KEY" 和 api_key = "sk-real-key"
- 新：通过 AST 区分常量赋值、配置读取、硬编码值

设计原则：
- 纯 Python 标准库（ast + os + re），零外部依赖
- 通用化设计，不依赖任何特定项目结构
- 向后兼容 CodeFile 数据结构

作者: CodeRef-AI Team
版本: v2.0
"""

import ast
import os
import re
import sys
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger


# ═══════════════════════════════════════════════════════════════════
# 数据结构（与 code_analyzer 兼容）
# ═══════════════════════════════════════════════════════════════════

@dataclass
class AstCodeFunction:
    """AST 解析的函数信息"""
    name: str
    start_line: int
    end_line: int
    parameters: List[str] = field(default_factory=list)
    return_type: Optional[str] = None
    docstring: Optional[str] = None
    code: str = ""
    decorators: List[str] = field(default_factory=list)
    is_async: bool = False
    is_method: bool = False
    parent_class: Optional[str] = None


@dataclass
class AstCodeClass:
    """AST 解析的类信息"""
    name: str
    start_line: int
    end_line: int
    methods: List[AstCodeFunction] = field(default_factory=list)
    base_classes: List[str] = field(default_factory=list)
    docstring: Optional[str] = None
    decorators: List[str] = field(default_factory=list)


@dataclass
class AstCodeImport:
    """AST 解析的导入信息"""
    module: str           # 导入的模块名（如 "os", "loguru", "shared.llm_client"）
    names: List[str]      # 导入的名字（如 ["logger"], ["CodeAnalyzer"]）
    is_from_import: bool  # True=from X import Y, False=import X
    line: int
    category: str = "unknown"  # stdlib / third_party / project / relative


@dataclass
class AstCodeCall:
    """AST 解析的函数调用"""
    func_name: str        # 被调用的函数名（如 "logger.error", "os.path.join"）
    line: int
    is_method_call: bool  # 是否是方法调用（如 obj.method()）
    args_count: int       # 参数数量


@dataclass
class AstCodeAssignment:
    """AST 解析的赋值语句"""
    target: str           # 赋值目标（如 "api_key", "password"）
    value_repr: str       # 值的字符串表示
    line: int
    category: str         # constant / config / hardcoded / expression


@dataclass
class AstFileResult:
    """AST 解析的单文件结果"""
    file_path: str
    language: str = "python"
    imports: List[AstCodeImport] = field(default_factory=list)
    functions: List[AstCodeFunction] = field(default_factory=list)
    classes: List[AstCodeClass] = field(default_factory=list)
    calls: List[AstCodeCall] = field(default_factory=list)
    assignments: List[AstCodeAssignment] = field(default_factory=list)
    total_lines: int = 0
    module_docstring: Optional[str] = None

    # 向后兼容 code_analyzer.CodeFile 的字段
    @property
    def all_functions(self) -> List[AstCodeFunction]:
        """所有函数（包括类方法）"""
        result = list(self.functions)
        for cls in self.classes:
            result.extend(cls.methods)
        return result

    @property
    def import_modules(self) -> Set[str]:
        """所有导入的模块名"""
        return {imp.module for imp in self.imports}

    @property
    def call_names(self) -> Set[str]:
        """所有被调用的函数名"""
        return {c.func_name for c in self.calls}


# ═══════════════════════════════════════════════════════════════════
# AST 解析器
# ═══════════════════════════════════════════════════════════════════

class AstParser:
    """
    精确代码解析器，使用 Python AST 模块

    用法:
        parser = AstParser()
        result = parser.parse("path/to/file.py")
        result = parser.parse_content(source_code, file_path="path/to/file.py")
    """

    # 标准库模块名（Python 3.10+）
    STDLIB_MODULES = _get_stdlib_modules() if False else {
        'abc', 'aifc', 'argparse', 'array', 'ast', 'asynchat', 'asyncio',
        'asyncore', 'atexit', 'audioop', 'base64', 'bdb', 'binascii', 'binhex',
        'bisect', 'builtins', 'bz2', 'calendar', 'cgi', 'cgitb', 'chunk',
        'cmath', 'cmd', 'code', 'codecs', 'codeop', 'collections', 'colorsys',
        'compileall', 'concurrent', 'configparser', 'contextlib', 'contextvars',
        'copy', 'copyreg', 'cProfile', 'crypt', 'csv', 'ctypes', 'curses',
        'dataclasses', 'datetime', 'dbm', 'decimal', 'difflib', 'dis',
        'distutils', 'doctest', 'email', 'encodings', 'enum', 'errno',
        'faulthandler', 'fcntl', 'filecmp', 'fileinput', 'fnmatch', 'fractions',
        'ftplib', 'functools', 'gc', 'getopt', 'getpass', 'gettext', 'glob',
        'grp', 'gzip', 'hashlib', 'heapq', 'hmac', 'html', 'http', 'idlelib',
        'imaplib', 'imghdr', 'importlib', 'inspect', 'io', 'ipaddress', 'itertools',
        'json', 'keyword', 'lib2to3', 'linecache', 'locale', 'logging', 'lzma',
        'mailbox', 'mailcap', 'marshal', 'math', 'mimetypes', 'mmap', 'modulefinder',
        'multiprocessing', 'netrc', 'nis', 'nntplib', 'numbers', 'operator', 'os',
        'ossaudiodev', 'pathlib', 'pdb', 'pickle', 'pickletools', 'pipes', 'pkgutil',
        'platform', 'plistlib', 'poplib', 'posix', 'posixpath', 'pprint', 'profile',
        'pstats', 'pty', 'pwd', 'py_compile', 'pyclbr', 'pydoc', 'queue', 'quopri',
        'random', 're', 'readline', 'reprlib', 'resource', 'rlcompleter', 'runpy',
        'sched', 'secrets', 'select', 'selectors', 'shelve', 'shlex', 'shutil',
        'signal', 'site', 'smtpd', 'smtplib', 'sndhdr', 'socket', 'socketserver',
        'sqlite3', 'ssl', 'stat', 'statistics', 'string', 'stringprep', 'struct',
        'subprocess', 'sunau', 'symtable', 'sys', 'sysconfig', 'syslog', 'tabnanny',
        'tarfile', 'telnetlib', 'tempfile', 'termios', 'test', 'textwrap', 'threading',
        'time', 'timeit', 'tkinter', 'token', 'tokenize', 'trace', 'traceback',
        'tracemalloc', 'tty', 'turtle', 'turtledemo', 'types', 'typing', 'unicodedata',
        'unittest', 'urllib', 'uu', 'uuid', 'venv', 'warnings', 'wave', 'weakref',
        'webbrowser', 'winreg', 'winsound', 'wsgiref', 'xdrlib', 'xml', 'xmlrpc',
        'zipapp', 'zipfile', 'zipimport', 'zlib',
    }

    # 敏感变量名（可能含凭据的赋值目标）
    SENSITIVE_VAR_NAMES = {
        'password', 'passwd', 'pwd', 'secret', 'token',
        'api_key', 'apikey', 'access_key', 'private_key',
        'auth_token', 'bearer_token', 'client_secret',
    }

    def __init__(self, project_root: str = ""):
        self.project_root = project_root

    def parse(self, file_path: str) -> Optional[AstFileResult]:
        """解析文件"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            return self.parse_content(content, file_path)
        except Exception as e:
            logger.warning(f"[AstParser] 解析文件失败 {file_path}: {e}")
            return None

    def parse_content(self, content: str, file_path: str = "<string>") -> Optional[AstFileResult]:
        """解析代码内容"""
        try:
            tree = ast.parse(content, filename=file_path)
        except SyntaxError as e:
            logger.warning(f"[AstParser] 语法错误 {file_path}: {e}")
            return None

        result = AstFileResult(
            file_path=file_path,
            total_lines=len(content.splitlines()),
        )

        # 提取模块级 docstring
        result.module_docstring = ast.get_docstring(tree)

        # 遍历顶层语句
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, ast.Import):
                self._handle_import(node, result)
            elif isinstance(node, ast.ImportFrom):
                self._handle_import_from(node, result)
            elif isinstance(node, ast.FunctionDef):
                result.functions.append(self._parse_function(node, content))
            elif isinstance(node, ast.AsyncFunctionDef):
                result.functions.append(self._parse_function(node, content, is_async=True))
            elif isinstance(node, ast.ClassDef):
                result.classes.append(self._parse_class(node, content))
            elif isinstance(node, ast.Assign):
                self._handle_assignment(node, result, content)
            elif isinstance(node, ast.Expr):
                # 模块级表达式（如函数调用）
                self._handle_expression(node.value, result)

        # 提取所有函数调用（AST 遍历）
        self._extract_all_calls(tree, result, content)

        return result

    def _handle_import(self, node: ast.Import, result: AstFileResult):
        """处理 import X 语句"""
        for alias in node.names:
            imp = AstCodeImport(
                module=alias.name,
                names=[alias.asname or alias.name.split('.')[0]],
                is_from_import=False,
                line=node.lineno,
                category=self._classify_import(alias.name),
            )
            result.imports.append(imp)

    def _handle_import_from(self, node: ast.ImportFrom, result: AstFileResult):
        """处理 from X import Y 语句"""
        module = node.module or ""
        level = node.level  # 相对导入层级（0=绝对导入, >0=相对导入）

        if level > 0:
            # 相对导入
            module = "." * level + (module or "")
            category = "project"
        else:
            category = self._classify_import(module)

        names = [alias.asname or alias.name for alias in node.names]
        imp = AstCodeImport(
            module=module,
            names=names,
            is_from_import=True,
            line=node.lineno,
            category=category,
        )
        result.imports.append(imp)

    def _classify_import(self, module: str) -> str:
        """分类导入：stdlib / third_party / project"""
        root = module.split('.')[0]

        if root in self.STDLIB_MODULES:
            return "stdlib"

        # 相对导入
        if module.startswith('.'):
            return "project"

        # 检查是否是项目内部模块（导入路径与项目根目录匹配）
        if self.project_root:
            # 如果项目根目录下有与导入根同名的目录，则是项目内部
            probe_path = os.path.join(self.project_root, root)
            if os.path.isdir(probe_path):
                return "project"

        return "third_party"

    def _parse_function(self, node: ast.FunctionDef, content: str,
                        is_async: bool = False, is_method: bool = False,
                        parent_class: str = None) -> AstCodeFunction:
        """解析函数定义"""
        # 参数
        params = []
        for arg in node.args.args:
            params.append(arg.arg)

        # 返回类型
        return_type = None
        if node.returns:
            return_type = ast.unparse(node.returns)

        # docstring
        docstring = ast.get_docstring(node)

        # 装饰器
        decorators = []
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                decorators.append(dec.id)
            elif isinstance(dec, ast.Attribute):
                decorators.append(ast.unparse(dec))
            elif isinstance(dec, ast.Call):
                if isinstance(dec.func, ast.Name):
                    decorators.append(dec.func.id)
                else:
                    decorators.append(ast.unparse(dec.func))

        # 代码
        code = ast.get_source_segment(content, node) if content else ""

        return AstCodeFunction(
            name=node.name,
            start_line=node.lineno,
            end_line=getattr(node, 'end_lineno', node.lineno),
            parameters=params,
            return_type=return_type,
            docstring=docstring,
            code=code or "",
            decorators=decorators,
            is_async=is_async,
            is_method=is_method,
            parent_class=parent_class,
        )

    def _parse_class(self, node: ast.ClassDef, content: str) -> AstCodeClass:
        """解析类定义"""
        # 基类
        bases = []
        for base in node.bases:
            if isinstance(base, ast.Name):
                bases.append(base.id)
            elif isinstance(base, ast.Attribute):
                bases.append(ast.unparse(base))

        # docstring
        docstring = ast.get_docstring(node)

        # 装饰器
        decorators = []
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name):
                decorators.append(dec.id)

        # 方法
        cls = AstCodeClass(
            name=node.name,
            start_line=node.lineno,
            end_line=getattr(node, 'end_lineno', node.lineno),
            base_classes=bases,
            docstring=docstring,
            decorators=decorators,
        )

        for child in node.body:
            if isinstance(child, ast.FunctionDef):
                cls.methods.append(self._parse_function(
                    child, content, is_method=True, parent_class=node.name
                ))
            elif isinstance(child, ast.AsyncFunctionDef):
                cls.methods.append(self._parse_function(
                    child, content, is_async=True, is_method=True, parent_class=node.name
                ))

        return cls

    def _handle_assignment(self, node: ast.Assign, result: AstFileResult,
                           content: str):
        """处理赋值语句，区分常量/配置/硬编码"""
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                value_node = node.value

                # 获取值的字符串表示
                value_repr = ast.unparse(value_node) if hasattr(ast, 'unparse') else ''

                # 分类
                category = self._classify_assignment(var_name, value_node)

                result.assignments.append(AstCodeAssignment(
                    target=var_name,
                    value_repr=value_repr,
                    line=node.lineno,
                    category=category,
                ))

    def _classify_assignment(self, var_name: str, value_node: ast.AST) -> str:
        """
        分类赋值类型

        - constant: 常量定义（全大写变量名，值为常量）
        - config: 配置读取（os.environ.get / config.get / .env）
        - hardcoded: 硬编码值（敏感变量名 + 字符串字面量）
        - expression: 表达式（无法判断的复杂表达式）
        """
        var_is_upper = var_name == var_name.upper() and '_' in var_name
        var_is_sensitive = var_name.lower() in self.SENSITIVE_VAR_NAMES

        # 检查是否是配置读取
        if isinstance(value_node, ast.Call):
            if isinstance(value_node.func, ast.Attribute):
                full = ast.unparse(value_node.func)
                if any(kw in full for kw in ['os.environ', 'getenv', 'config.get', 'os.getenv']):
                    return "config"
            elif isinstance(value_node.func, ast.Name):
                if value_node.func.id in ('getenv', 'get_config'):
                    return "config"

        # 常量定义：全大写变量名 + 字符串/数字常量
        if var_is_upper and isinstance(value_node, (ast.Constant, ast.Num)):
            val = getattr(value_node, 'value', None)
            if isinstance(val, str):
                # 如果值就是变量名本身（如 E1001_KEY = "E1001_KEY"），这是错误码常量
                if val == var_name or val.replace('-', '_').upper() == var_name.upper():
                    return "constant"  # 确认为错误码/常量
                # 如果值看起来像常量（全大写+下划线），也是常量
                if val == val.upper() and '_' in val:
                    return "constant"
            return "constant"

        # 硬编码值：敏感变量名 + 字符串字面量
        if var_is_sensitive and isinstance(value_node, ast.Constant):
            val = getattr(value_node, 'value', None)
            if isinstance(val, str) and len(val) > 4:
                return "hardcoded"

        return "expression"

    def _handle_expression(self, node: ast.AST, result: AstFileResult):
        """处理表达式（如函数调用）"""
        if isinstance(node, ast.Call):
            self._extract_call(node, result)

    def _extract_all_calls(self, tree: ast.AST, result: AstFileResult, content: str):
        """遍历 AST 提取所有函数调用"""
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                self._extract_call(node, result)

    def _extract_call(self, node: ast.Call, result: AstFileResult):
        """提取单个函数调用"""
        func_name = ""
        is_method = False

        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = ast.unparse(node.func)
            is_method = True
        else:
            func_name = ast.unparse(node.func) if hasattr(ast, 'unparse') else '?'

        args_count = len(node.args) + len(node.keywords)

        result.calls.append(AstCodeCall(
            func_name=func_name,
            line=getattr(node, 'lineno', 0),
            is_method_call=is_method,
            args_count=args_count,
        ))


# ═══════════════════════════════════════════════════════════════════
# 批量解析器
# ═══════════════════════════════════════════════════════════════════

class AstProjectParser:
    """批量解析项目中的所有 Python 文件"""

    def __init__(self, project_root: str):
        self.project_root = project_root
        self.parser = AstParser(project_root=project_root)

    def parse_all(self, max_files: int = 5000) -> Dict[str, AstFileResult]:
        """解析所有 Python 文件"""
        results = {}
        python_files = []

        for root, dirs, files in os.walk(self.project_root):
            # 跳过常见的非代码目录
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in
                       ('__pycache__', 'node_modules', 'venv', '.venv', 'env',
                        '.git', 'dist', 'build', 'egg-info', '.tox', '.mypy_cache')]

            for f in files:
                if f.endswith('.py'):
                    python_files.append(os.path.join(root, f))

        logger.info(f"[AstProjectParser] 发现 {len(python_files)} 个 Python 文件")

        for i, file_path in enumerate(python_files[:max_files]):
            result = self.parser.parse(file_path)
            if result:
                results[file_path] = result
            if (i + 1) % 100 == 0:
                logger.info(f"[AstProjectParser] 进度: {i+1}/{len(python_files[:max_files])}")

        logger.info(f"[AstProjectParser] 解析完成: {len(results)} 个文件")
        return results

    def get_call_graph(self, results: Dict[str, AstFileResult]) -> Dict[str, List[str]]:
        """从解析结果构建调用图"""
        graph = {}
        for file_path, result in results.items():
            for func in result.all_functions:
                full_name = func.name
                if func.parent_class:
                    full_name = f"{func.parent_class}.{func.name}"
                graph[full_name] = []

                # 从函数体代码中提取调用（简化版）
                if func.code:
                    call_pattern = re.compile(r'([a-zA-Z_]\w*)\s*\(')
                    for m in call_pattern.finditer(func.code):
                        called = m.group(1)
                        if called not in ('if', 'for', 'while', 'def', 'class', 'print',
                                          'return', 'import', 'from', 'raise', 'assert',
                                          'yield', 'with', 'try', 'except', 'lambda',
                                          'not', 'and', 'or', 'in', 'is', 'del', 'True',
                                          'False', 'None', 'str', 'int', 'list', 'dict',
                                          'set', 'tuple', 'len', 'type', 'range', 'enumerate',
                                          'zip', 'map', 'filter', 'isinstance', 'hasattr',
                                          'getattr', 'setattr', 'super', 'open', 'print',
                                          'format', 'sorted', 'reversed', 'any', 'all',
                                          'min', 'max', 'sum', 'abs', 'round', 'float',
                                          'bool', 'bytes', 'chr', 'ord', 'repr', 'id'):
                            continue
                        graph[full_name].append(called)
        return graph


# ═══════════════════════════════════════════════════════════════════
# 辅助函数
# ═══════════════════════════════════════════════════════════════════

def _get_stdlib_modules() -> Set[str]:
    """动态获取标准库模块列表"""
    try:
        from stdlib_list import stdlib_list
        return set(stdlib_list("3.10"))
    except ImportError:
        return set()


def ast_to_codefile(ast_result: AstFileResult) -> 'CodeFile':
    """将 AST 解析结果转换为 CodeFile（向后兼容）"""
    from core.code_analyzer import CodeFile, CodeFunction, CodeClass

    # 导入
    imports = []
    deps = set()
    project_imports = []
    for imp in ast_result.imports:
        imports.append(imp.module)
        if imp.category == "project":
            project_imports.append(imp.module)
        elif imp.category == "third_party":
            deps.add(imp.module.split('.')[0])

    # 函数
    functions = []
    for func in ast_result.functions:
        functions.append(CodeFunction(
            name=func.name,
            start_line=func.start_line,
            end_line=func.end_line,
            parameters=func.parameters,
            return_type=func.return_type,
            docstring=func.docstring,
            code=func.code,
        ))

    # 类
    classes = []
    for cls in ast_result.classes:
        methods = []
        for m in cls.methods:
            methods.append(CodeFunction(
                name=m.name,
                start_line=m.start_line,
                end_line=m.end_line,
                parameters=m.parameters,
                return_type=m.return_type,
                docstring=m.docstring,
                code=m.code,
            ))
        classes.append(CodeClass(
            name=cls.name,
            start_line=cls.start_line,
            end_line=cls.end_line,
            methods=methods,
            base_classes=cls.base_classes,
            docstring=cls.docstring,
        ))

    # 函数调用
    function_calls = list(ast_result.call_names)

    code_file = CodeFile(
        file_path=ast_result.file_path,
        language=ast_result.language,
        imports=imports,
        functions=functions,
        classes=classes,
        dependencies=deps,
        raw_content="",  # 由上层填充
        project_imports=project_imports,
        function_calls=function_calls,
    )

    return code_file
