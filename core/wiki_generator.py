# -*- coding: utf-8 -*-
"""
Wiki Generator —— 面向不懂代码的 AI 辅助开发者的项目 Wiki 生成器

基于 LLM 理解代码语义，生成结构化多文档 Wiki，替代旧版机械 docstring 搬运。
借鉴 ai-codebase-scribe 和 readme-llm-generator 的设计理念。

输出结构：
  docs/wiki/
  ├── README.md           # 项目概述（给老板/同事看的）
  ├── ARCHITECTURE.md     # 架构设计（技术全景）
  ├── INSTALLATION.md     # 安装指南（手把手）
  ├── USAGE.md            # 使用指南（怎么用）
  ├── MODULES/            # 模块详解
  │   ├── _index.md       # 模块索引
  │   ├── core.md         # 核心模块
  │   └── ...             # 每个模块一页
  ├── API.md              # API 文档（如有 Web 框架）
  └── WIKI_INDEX.md       # 导航首页

特性：
- LLM 驱动：让 AI 理解代码语义，而非机械搬运 docstring
- 大仓库支持：>300 文件自动切换采样模式，优先核心文件
- Git Hook 配置：可选安装 post-commit hook 自动更新 wiki
- 通俗语言：面向不懂代码的用户，解释"做什么"而不只是"是什么"

作者: CodeRef Team
版本: v2.0 (升级自 generate_docs)
"""

import os
import re
import ast
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict


# ═══════════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════════

@dataclass
class WikiModule:
    """Wiki 模块信息"""
    name: str
    path: str
    py_files: List[str]
    file_count: int
    is_core: bool = False
    description: str = ""


@dataclass
class WikiResult:
    """Wiki 生成结果"""
    project_path: str
    project_name: str
    output_dir: str
    wiki_style: str = "comprehensive"
    documents: List[str] = field(default_factory=list)
    module_count: int = 0
    total_files: int = 0
    large_repo: bool = False
    subprojects: List[str] = field(default_factory=list)
    subproject_results: List[Dict] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════════════
# 多级管线元数据结构
# ═══════════════════════════════════════════════════════════════════

@dataclass
class CodeFileMetadata:
    """单文件 AST 元数据（约原代码 5-10% 体积）"""
    rel_path: str
    docstring: str = ""
    classes: List[Dict] = field(default_factory=list)
    functions: List[Dict] = field(default_factory=list)
    imports: List[str] = field(default_factory=list)
    has_main_block: bool = False
    is_entry_point: bool = False


@dataclass
class ModuleCodeMetadata:
    """模块级的元数据聚合"""
    name: str
    path: str
    files: List[CodeFileMetadata] = field(default_factory=list)
    total_files: int = 0


@dataclass
class ProjectCodeMetadata:
    """项目级元数据"""
    project_path: str
    modules: List[ModuleCodeMetadata] = field(default_factory=list)
    total_files: int = 0
    has_web_framework: bool = False


# ═══════════════════════════════════════════════════════════════════
# Wiki 生成器
# ═══════════════════════════════════════════════════════════════════

class WikiGenerator:
    """项目 Wiki 生成器"""

    # 大仓库阈值
    LARGE_REPO_THRESHOLD = 300
    # 大仓库采样上限
    LARGE_REPO_SAMPLE = 150
    # 每个模块最多采样的文件数
    MAX_FILES_PER_MODULE = 30
    # LLM 单次最大输入字符数（避免 token 超限）
    MAX_CONTEXT_CHARS = 40000

    # ─── 核心模块判定规则（可配置，AI 可追加）───
    # 默认入口文件名
    DEFAULT_ENTRY_FILES = ["main.py", "app.py", "server.py", "run.py", "__init__.py"]
    # 默认文件数阈值
    DEFAULT_MIN_FILES = 10
    # 规则配置文件（相对于项目 cache）
    CORE_RULES_FILE = "core_rules.json"

    @staticmethod
    def _core_rules_path(project_path: str) -> str:
        """核心模块规则配置文件路径"""
        import hashlib
        ph = hashlib.md5(os.path.abspath(project_path).encode()).hexdigest()[:12]
        d = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "cache", "pipeline")
        os.makedirs(d, exist_ok=True)
        return os.path.join(d, f"core_rules_{ph}.json")

    def _load_core_rules(self, project_path: str) -> dict:
        """加载核心模块判定规则（默认值 + 配置文件覆盖）"""
        rules = {
            "entry_files": list(self.DEFAULT_ENTRY_FILES),
            "core_names": [],
            "min_files": self.DEFAULT_MIN_FILES,
        }
        path = self._core_rules_path(project_path)
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    saved = json.load(f)
                if "entry_files" in saved:
                    rules["entry_files"] = saved["entry_files"]
                if "core_names" in saved:
                    rules["core_names"] = saved["core_names"]
                if "min_files" in saved:
                    rules["min_files"] = saved["min_files"]
            except Exception:
                pass
        return rules

    @staticmethod
    def save_core_rules(project_path: str, rules: dict) -> bool:
        """保存核心模块判定规则（供 AI 调用）"""
        try:
            path = WikiGenerator._core_rules_path(project_path)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(rules, f, ensure_ascii=False, indent=1)
            return True
        except Exception:
            return False

    @staticmethod
    def get_core_rules(project_path: str) -> dict:
        """获取当前核心模块判定规则（供 AI 查看）"""
        wg = WikiGenerator()
        return wg._load_core_rules(project_path)

    # 排除的目录名
    EXCLUDE_DIRS = {
        "__pycache__", "node_modules", ".git", "venv", ".venv", "env",
        "Lib", "lib", "lib64", "site-packages", "dist-packages",
        "third_party", ".gitnexus", "data", "docs", "reports",
        "cache", "coderef-report", "logs", "build", "dist",
        ".pytest_cache", ".mypy_cache", ".ruff_cache", ".tox",
    }

    # 子项目指示器：包含这些文件的子目录视为独立子项目
    SUBPROJECT_INDICATORS = ["requirements.txt", "pyproject.toml", "setup.py"]

    # Wiki 风格定义
    WIKI_STYLES = {
        "comprehensive": "详细全面，面向非程序员，用通俗语言解释一切",
        "reference": "精简参考，面向有经验的开发者，快速查阅关键信息",
        "tutorial": "教程风格，逐步引导，适合新手学习项目",
        "plain": "极简风格，最短说明，只保留核心要点",
    }

    def __init__(self, llm_client=None):
        """初始化生成器。
        
        Args:
            llm_client: LLMIntegration 实例，如果为 None 则延迟创建
        """
        self._llm = llm_client

    @property
    def llm(self):
        """延迟加载 LLM 客户端"""
        if self._llm is None:
            from core.llm_integration import LLMIntegration
            self._llm = LLMIntegration()
        return self._llm

    # ─── 主入口 ───

    def generate(self, project_path: str, output_dir: str = "",
                 enable_git_hook: bool = False,
                 wiki_style: str = "comprehensive",
                 include_subprojects: bool = False) -> WikiResult:
        """生成项目 Wiki
        
        Args:
            project_path: 项目根目录
            output_dir: 输出目录，默认 {project_path}/docs/wiki/
            enable_git_hook: 是否安装 git post-commit hook
            wiki_style: Wiki 风格 (comprehensive / reference / tutorial / plain)
            include_subprojects: 是否同时为子项目生成独立 Wiki
        
        Returns:
            WikiResult: 生成结果
        """
        project_path = os.path.abspath(project_path)
        project_name = os.path.basename(project_path)

        # 验证风格参数
        if wiki_style not in self.WIKI_STYLES:
            wiki_style = "comprehensive"

        if not output_dir:
            output_dir = os.path.join(project_path, "docs", "wiki")

        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(os.path.join(output_dir, "MODULES"), exist_ok=True)

        result = WikiResult(
            project_path=project_path,
            project_name=project_name,
            output_dir=output_dir,
            wiki_style=wiki_style,
        )

        # 0. 发现子项目
        if include_subprojects:
            subprojects = self._discover_subprojects(project_path)
            result.subprojects = subprojects

        # 1. 发现模块
        modules = self._discover_modules(project_path)
        result.total_files = sum(m.file_count for m in modules)

        if not modules:
            result.errors.append("未发现任何 Python 模块")
            return result

        # 2. 判断大仓库模式（旧采样保留用于模块发现，元数据不采样）
        if result.total_files > self.LARGE_REPO_THRESHOLD:
            result.large_repo = True
            modules = self._sample_large_repo(modules)

        # ─── 三级管线 ───

        # Stage 1: 全量代码元数据提取（AST，无 LLM）
        code_metadata = self._build_code_metadata(modules, project_path)

        # 超大仓库时对元数据采样降级（但仍比原始代码采样损失小得多）
        if result.large_repo:
            code_metadata = self._sample_metadata(code_metadata)

        # Stage 2: LLM 逐模块归纳描述（从全量元数据写，不丢失信息）
        module_descriptions = self._generate_module_descriptions(code_metadata, wiki_style)

        # Stage 3: LLM 生成各文档（用 Stage 2 的输出，而非原始代码摘要）
        docs = self._generate_all_documents(
            project_name, modules, code_metadata, module_descriptions,
            output_dir, result,
        )
        result.documents = docs

        # 5. 子项目 Wiki（同样使用三级管线）
        if include_subprojects and subprojects:
            for sub_path in subprojects:
                sub_name = os.path.basename(sub_path)
                sub_output = os.path.join(output_dir, "subprojects", sub_name)
                os.makedirs(sub_output, exist_ok=True)
                os.makedirs(os.path.join(sub_output, "MODULES"), exist_ok=True)

                sub_result = WikiResult(
                    project_path=sub_path,
                    project_name=sub_name,
                    output_dir=sub_output,
                    wiki_style=wiki_style,
                )

                sub_modules = self._discover_modules(sub_path)
                sub_result.total_files = sum(m.file_count for m in sub_modules)

                if sub_modules:
                    if sub_result.total_files > self.LARGE_REPO_THRESHOLD:
                        sub_result.large_repo = True
                        sub_modules = self._sample_large_repo(sub_modules)

                    # Stage 1
                    sub_meta = self._build_code_metadata(sub_modules, sub_path)
                    if sub_result.large_repo:
                        sub_meta = self._sample_metadata(sub_meta)
                    # Stage 2
                    sub_descriptions = self._generate_module_descriptions(sub_meta, wiki_style)
                    # Stage 3
                    sub_docs = self._generate_all_documents(
                        sub_name, sub_modules, sub_meta, sub_descriptions,
                        sub_output, sub_result,
                    )
                    sub_result.documents = sub_docs
                    sub_result.module_count = sum(1 for d in sub_docs if "MODULES" in d)

                result.subproject_results.append({
                    "name": sub_name,
                    "path": sub_path,
                    "documents": len(sub_result.documents),
                    "total_files": sub_result.total_files,
                    "large_repo": sub_result.large_repo,
                })

        # 6. Git hook 配置
        if enable_git_hook:
            self._setup_git_hook(project_path, output_dir)

        return result

    # ─── 模块发现 ───

    def _discover_modules(self, project_path: str) -> List[WikiModule]:
        """发现项目中的 Python 模块"""
        modules = []

        # 先检查根目录下的 .py 文件
        root_py_files = []
        for entry in os.scandir(project_path):
            if entry.is_file() and entry.name.endswith(".py") and not entry.name.startswith("_"):
                root_py_files.append(entry.path)

        if root_py_files:
            modules.append(WikiModule(
                name="root",
                path=project_path,
                py_files=root_py_files,
                file_count=len(root_py_files),
                is_core=True,
            ))

        # 再检查子目录
        for entry in os.scandir(project_path):
            if not entry.is_dir():
                continue
            if entry.name.startswith(".") or entry.name.startswith("_"):
                continue
            if entry.name in self.EXCLUDE_DIRS:
                continue
            if entry.name.startswith(("Python3.", "Python2.", "pypy", ".git")):
                continue

            py_files = self._collect_py_files(entry.path)
            if py_files:
                # 加载可配置的核心模块判定规则
                core_rules = self._load_core_rules(project_path)
                entry_files = core_rules.get("entry_files", self.DEFAULT_ENTRY_FILES)
                core_names = core_rules.get("core_names", [])
                min_files = core_rules.get("min_files", self.DEFAULT_MIN_FILES)

                # 判断是否核心模块：
                # 1. 模块名在 AI 指定的 core_names 中
                # 2. 包含入口文件（可配置列表）
                # 3. 文件数量 >= min_files 阈值
                is_core = (
                    entry.name in core_names or
                    any(os.path.basename(f) in entry_files for f in py_files) or
                    len(py_files) >= min_files
                )
                modules.append(WikiModule(
                    name=entry.name,
                    path=entry.path,
                    py_files=py_files,
                    file_count=len(py_files),
                    is_core=is_core,
                ))

        return modules

    def _collect_py_files(self, dir_path: str) -> List[str]:
        """收集目录下的 Python 文件"""
        py_files = []
        for root, dirs, files in os.walk(dir_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in self.EXCLUDE_DIRS]
            for f in files:
                if f.endswith(".py") and not f.startswith("_"):
                    py_files.append(os.path.join(root, f))
            if len(py_files) > self.MAX_FILES_PER_MODULE:
                break
        return py_files

    def _discover_subprojects(self, project_path: str) -> List[str]:
        """发现大项目中的子项目（monorepo 支持）

        检测子目录中是否包含独立的依赖文件（requirements.txt /
        pyproject.toml / setup.py），如果有则视为独立子项目。
        限定深度为 2 层，避免过度递归。
        """
        subprojects = []
        max_depth = 2

        def _scan(dir_path: str, depth: int):
            if depth > max_depth:
                return
            try:
                for entry in os.scandir(dir_path):
                    if not entry.is_dir():
                        continue
                    if entry.name.startswith(".") or entry.name.startswith("_"):
                        continue
                    if entry.name in self.EXCLUDE_DIRS:
                        continue

                    # 检查是否为子项目
                    for indicator in self.SUBPROJECT_INDICATORS:
                        if os.path.isfile(os.path.join(entry.path, indicator)):
                            subprojects.append(entry.path)
                            break
                    else:
                        # 不是子项目，继续深入
                        _scan(entry.path, depth + 1)
            except PermissionError:
                pass

        _scan(project_path, 1)
        return subprojects

    # ═══════════════════════════════════════════════════════════════════
    # 三级管线：Stage 1 — 全量代码元数据提取（AST，无 LLM）
    # ═══════════════════════════════════════════════════════════════════

    def _coderef_cache_dir(self) -> str:
        """返回 CodeRef 自身的 cache 目录（用于存元数据，不污染目标项目）"""
        script_dir = os.path.dirname(os.path.abspath(__file__))
        cache_dir = os.path.join(os.path.dirname(script_dir), "cache", "wiki_cache")
        os.makedirs(cache_dir, exist_ok=True)
        return cache_dir

    def _project_cache_path(self, project_path: str) -> str:
        """返回某项目的 cache 子目录"""
        h = hashlib.md5(project_path.encode("utf-8")).hexdigest()[:8]
        p = os.path.join(self._coderef_cache_dir(), h)
        os.makedirs(p, exist_ok=True)
        return p

    def _build_code_metadata(self, modules: List[WikiModule], project_path: str,
                             skip_cache: bool = False) -> ProjectCodeMetadata:
        """Stage 1：对全部 .py 文件执行 AST 扫描，输出结构化元数据

        - 不采样、不截断，所有文件全部扫描
        - 元数据约为原始代码 5-10% 体积
        - 缓存到 CodeRef cache 目录，重复调用不重复扫描
        """
        cache_dir = self._project_cache_path(project_path)
        cache_file = os.path.join(cache_dir, "stage1_metadata.json")

        # 如果缓存存在且有效，直接加载
        if not skip_cache and os.path.exists(cache_file):
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                meta = self._metadata_from_dict(raw)
                if meta and len(meta.modules) == len(modules):
                    return meta
            except Exception:
                pass

        web_framework_kws = {"fastapi", "django", "flask", "sanic", "tornado",
                             "aiohttp", "starlette", "bottle", "falcon"}
        has_web = False
        mod_metas: List[ModuleCodeMetadata] = []

        for mod in modules:
            files_meta: List[CodeFileMetadata] = []
            for fpath in sorted(mod.py_files):
                rel = os.path.relpath(fpath, mod.path)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except (OSError, IOError):
                    continue

                fm = self._extract_file_metadata(content, rel)
                files_meta.append(fm)

                # 检查 Web 框架
                if not has_web:
                    for imp in fm.imports:
                        if imp.lower() in web_framework_kws:
                            has_web = True
                            break

            mod_metas.append(ModuleCodeMetadata(
                name=mod.name,
                path=mod.path,
                files=files_meta,
                total_files=len(files_meta),
            ))

        meta = ProjectCodeMetadata(
            project_path=project_path,
            modules=mod_metas,
            total_files=sum(m.total_files for m in mod_metas),
            has_web_framework=has_web,
        )

        # 缓存
        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(self._metadata_to_dict(meta), f, ensure_ascii=False, indent=1)
        except Exception:
            pass

        return meta

    def _extract_file_metadata(self, content: str, rel_path: str) -> CodeFileMetadata:
        """从文件内容中提取结构化元数据（AST 扫描）"""
        fm = CodeFileMetadata(rel_path=rel_path)

        try:
            tree = ast.parse(content)

            # docstring
            doc = ast.get_docstring(tree)
            if doc:
                fm.docstring = doc.strip()[:300]

            # 类
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    bases = []
                    for b in node.bases:
                        if isinstance(b, ast.Name):
                            bases.append(b.id)
                        elif isinstance(b, ast.Attribute):
                            bases.append(b.attr)
                        elif isinstance(b, ast.Subscript) and isinstance(b.value, ast.Name):
                            bases.append(b.value.id)
                        else:
                            bases.append("?")
                    cls_doc = ast.get_docstring(node) or ""
                    methods = [
                        n.name for n in node.body
                        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
                        and not n.name.startswith("_")
                    ]
                    fm.classes.append({
                        "name": node.name,
                        "bases": bases,
                        "doc": cls_doc.strip()[:200],
                        "methods": methods[:10],  # 只保留前 10 个
                    })

            # 顶层函数
            for node in ast.iter_child_nodes(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_doc = ast.get_docstring(node) or ""
                    params = [arg.arg for arg in node.args.args[:8]]
                    fm.functions.append({
                        "name": node.name,
                        "params": params,
                        "doc": func_doc.strip()[:200],
                    })

            # import 依赖
            imports = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module.split(".")[0])
            fm.imports = sorted(imports)

            # 是否有 main 入口
            for node in ast.iter_child_nodes(tree):
                if isinstance(node, ast.If):
                    if (isinstance(node.test, ast.Compare)
                            and isinstance(node.test.left, ast.Name)
                            and node.test.left.id == "__name__"):
                        fm.has_main_block = True
                        break

            # 是否入口文件
            base = os.path.basename(rel_path)
            fm.is_entry_point = base in ("main.py", "app.py", "server.py", "run.py")

        except SyntaxError:
            pass

        return fm

    def _metadata_to_dict(self, meta: ProjectCodeMetadata) -> Dict:
        """ProjectCodeMetadata → dict（用于 JSON 缓存）"""
        return {
            "project_path": meta.project_path,
            "total_files": meta.total_files,
            "has_web_framework": meta.has_web_framework,
            "modules": [
                {
                    "name": m.name,
                    "path": m.path,
                    "total_files": m.total_files,
                    "files": [
                        {
                            "rel_path": f.rel_path,
                            "docstring": f.docstring,
                            "classes": f.classes,
                            "functions": f.functions,
                            "imports": f.imports,
                            "has_main_block": f.has_main_block,
                            "is_entry_point": f.is_entry_point,
                        }
                        for f in m.files
                    ],
                }
                for m in meta.modules
            ],
        }

    def _metadata_from_dict(self, d: Dict) -> Optional[ProjectCodeMetadata]:
        """dict → ProjectCodeMetadata（从 JSON 缓存恢复）"""
        try:
            modules = []
            for md in d.get("modules", []):
                files = [
                    CodeFileMetadata(**ff)
                    for ff in md.get("files", [])
                ]
                modules.append(ModuleCodeMetadata(
                    name=md["name"],
                    path=md["path"],
                    files=files,
                    total_files=md.get("total_files", len(files)),
                ))
            return ProjectCodeMetadata(
                project_path=d.get("project_path", ""),
                modules=modules,
                total_files=d.get("total_files", 0),
                has_web_framework=d.get("has_web_framework", False),
            )
        except Exception:
            return None

    # ═══════════════════════════════════════════════════════════════════
    # 三级管线：Stage 1b — 采样（超大仓库时元数据降级）
    # ═══════════════════════════════════════════════════════════════════

    METADATA_MAX_FILES = 500   # 单个模块元数据文件上限
    METADATA_MAX_CLASSES = 20  # 单个文件最多保留的类
    METADATA_MAX_FUNCS = 30    # 单个文件最多保留的函数

    def _sample_metadata(self, meta: ProjectCodeMetadata) -> ProjectCodeMetadata:
        """超大项目时对元数据进行采样（比采样原始代码损失小得多）"""
        for mod in meta.modules:
            if mod.total_files > self.METADATA_MAX_FILES:
                mod.files = mod.files[:self.METADATA_MAX_FILES]
            for f in mod.files:
                if len(f.classes) > self.METADATA_MAX_CLASSES:
                    f.classes = f.classes[:self.METADATA_MAX_CLASSES]
                if len(f.functions) > self.METADATA_MAX_FUNCS:
                    f.functions = f.functions[:self.METADATA_MAX_FUNCS]
        return meta

    # ═══════════════════════════════════════════════════════════════════
    # 三级管线：Stage 2 — LLM 写模块描述（从全量元数据归纳）
    # ═══════════════════════════════════════════════════════════════════

    def _generate_module_descriptions(self, meta: ProjectCodeMetadata,
                                       style: str) -> Dict[str, str]:
        """Stage 2：对每个模块，LLM 从全量元数据归纳出模块描述

        元数据比原始代码紧凑 10-20 倍，因此 LLM 可以看到所有文件。
        输出缓存到 CodeRef cache 避免重复调用。
        """
        cache_dir = self._project_cache_path(meta.project_path)
        cache_file = os.path.join(cache_dir, f"stage2_descriptions_{style}.json")
        if os.path.exists(cache_file):
            try:
                with open(cache_file, "r", encoding="utf-8") as f:
                    cached = json.load(f)
                if len(cached) == len(meta.modules):
                    return cached
            except Exception:
                pass

        # 生成项目级概览元数据（紧凑形式）
        overview_lines = [f"项目: {os.path.basename(meta.project_path)}"]
        overview_lines.append(f"总文件数: {meta.total_files}, 模块数: {len(meta.modules)}")
        overview_lines.append(f"Web 框架: {'检测到' if meta.has_web_framework else '未检测到'}")
        overview_lines.append("")

        for mod in meta.modules:
            # 计算元数据行数判断是否超限
            md_text = self._module_metadata_to_text(mod)
            overview_lines.append(f"--- 模块: {mod.name} ({mod.total_files} 文件) ---")
            overview_lines.append(md_text)
            overview_lines.append("")

        full_metadata = "\n".join(overview_lines)

        guidelines = self._style_guidelines(style)
        descriptions = {}

        for mod in meta.modules:
            md_text = self._module_metadata_to_text(mod)

            # 风格区分
            if style in ("reference", "plain"):
                # 硬核/极简：直接让 LLM 从元数据浓缩
                system_prompt = (
                    f"你是一个代码分析助手。基于下方元数据，用中文简要描述此模块。"
                    f"{guidelines}"
                    "输出纯 Markdown，直接列出关键信息。"
                )
            else:
                # comprehensive / tutorial：归纳为通俗语言
                system_prompt = (
                    f"你是一个代码分析助手。基于下方元数据，用通俗语言描述此模块。"
                    f"{guidelines}"
                    "要求：基于事实归纳，不要虚构任何类/函数/依赖。"
                    "输出纯 Markdown。"
                )

            user_prompt = (
                f"请描述模块 **{mod.name}** ({mod.total_files} 个 Python 文件, {len(md_text)} 字符元数据)。\n\n"
                f"元数据：\n```\n{md_text[:20000]}\n```\n\n"
                f"输出模块描述（不要包含 '基于元数据' 之类的前缀，直接输出内容）。"
            )

            desc = self._llm_ask(system_prompt, user_prompt)
            descriptions[mod.name] = desc

        # 缓存
        try:
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(descriptions, f, ensure_ascii=False, indent=1)
        except Exception:
            pass

        return descriptions

    def _module_metadata_to_text(self, mod: ModuleCodeMetadata) -> str:
        """将模块元数据转为紧凑文本"""
        lines = []
        for f in mod.files:
            parts = [f"## {f.rel_path}"]
            if f.docstring:
                parts.append(f"  doc: {f.docstring[:200]}")
            if f.is_entry_point:
                parts.append(f"  [入口文件]")
            if f.classes:
                for c in f.classes:
                    bases = f"({', '.join(c['bases'])})" if c["bases"] else ""
                    doc = f": {c['doc']}" if c["doc"] else ""
                    methods = f" [方法: {', '.join(c['methods'][:6])}]" if c["methods"] else ""
                    parts.append(f"  class {c['name']}{bases}{doc}{methods}")
            if f.functions:
                for fn in f.functions:
                    params = f"({', '.join(fn['params'])})" if fn["params"] else "()"
                    doc = f": {fn['doc']}" if fn["doc"] else ""
                    parts.append(f"  def {fn['name']}{params}{doc}")
            if f.imports:
                parts.append(f"  依赖: {', '.join(f.imports[:10])}")
            lines.extend(parts)
        return "\n".join(lines)

    # ─── 旧版代码摘要（保留作为回退） ───

    def _sample_large_repo(self, modules: List[WikiModule]) -> List[WikiModule]:
        """大仓库采样：优先核心模块，非核心模块采样"""
        # 核心模块优先保留全部
        core_modules = [m for m in modules if m.is_core]
        non_core = [m for m in modules if not m.is_core]

        import random
        random.seed(42)  # 确定性采样

        # 对非核心模块采样
        for m in non_core:
            if len(m.py_files) > 15:
                m.py_files = random.sample(m.py_files, 15)
                m.file_count = len(m.py_files)

        # 如果总文件数还是太多，对核心模块也采样
        total = sum(m.file_count for m in modules)
        if total > self.LARGE_REPO_SAMPLE:
            for m in core_modules:
                if len(m.py_files) > 20:
                    m.py_files = random.sample(m.py_files, 20)
                    m.file_count = len(m.py_files)

        return modules

    # ─── 代码摘要收集（旧版，保留回退） ───

    def _collect_code_summaries(self, modules: List[WikiModule]) -> Dict[str, str]:
        """收集每个模块的代码摘要文本（供 LLM 分析）"""
        summaries = {}

        for mod in modules:
            parts = [f"## 模块: {mod.name}\n"]
            parts.append(f"文件数: {mod.file_count}\n")

            for fpath in sorted(mod.py_files)[:20]:
                rel = os.path.relpath(fpath, mod.path)
                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except (OSError, IOError):
                    continue

                # 提取关键信息
                info = self._extract_file_info(content, rel)
                parts.append(info)

                # 控制总长度
                if sum(len(p) for p in parts) > self.MAX_CONTEXT_CHARS:
                    parts.append(f"\n...(还有 {len(mod.py_files) - 20} 个文件未列出)\n")
                    break

            summaries[mod.name] = "\n".join(parts)

        return summaries

    def _extract_file_info(self, content: str, rel_path: str) -> str:
        """从文件内容中提取关键信息"""
        lines = [f"\n### `{rel_path}`\n"]

        try:
            tree = ast.parse(content)

            # 模块 docstring
            doc = ast.get_docstring(tree)
            if doc:
                lines.append(f"**用途**: {doc.strip()[:200]}\n")

            # 类定义
            classes = []
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    bases = [
                        b.id if isinstance(b, ast.Name)
                        else b.attr if isinstance(b, ast.Attribute)
                        else str(b)
                        for b in node.bases
                    ]
                    doc = ast.get_docstring(node)
                    cls_info = f"- **class `{node.name}`**"
                    if bases:
                        cls_info += f"({', '.join(bases)})"
                    if doc:
                        cls_info += f": {doc.strip()[:100]}"
                    # 公开方法
                    public_methods = [
                        n.name for n in node.body
                        if isinstance(n, ast.FunctionDef) and not n.name.startswith("_")
                    ]
                    if public_methods:
                        cls_info += f" (方法: {', '.join(public_methods[:5])})"
                    classes.append(cls_info)

            if classes:
                lines.append("**类**:")
                lines.extend(classes[:5])
                if len(classes) > 5:
                    lines.append(f"  ...还有 {len(classes) - 5} 个类")
                lines.append("")

            # 函数定义
            functions = []
            for node in ast.iter_child_nodes(tree):
                if isinstance(node, ast.FunctionDef) and not node.name.startswith("_"):
                    doc = ast.get_docstring(node)
                    func_info = f"- **`{node.name}()`**"
                    if doc:
                        func_info += f": {doc.strip()[:100]}"
                    functions.append(func_info)

            if functions:
                lines.append("**函数**:")
                lines.extend(functions[:8])
                if len(functions) > 8:
                    lines.append(f"  ...还有 {len(functions) - 8} 个函数")
                lines.append("")

            # import 依赖
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.append(node.module.split(".")[0])

            if imports:
                unique_imports = list(set(imports))[:10]
                lines.append(f"**依赖**: {', '.join(unique_imports)}")
                lines.append("")

        except SyntaxError:
            lines.append("(*无法解析 AST，可能包含语法错误*)\n")

        return "\n".join(lines)

    # ─── LLM 文档生成 ───

    def _generate_all_documents(self, project_name: str, modules: List[WikiModule],
                                 meta: ProjectCodeMetadata,
                                 descriptions: Dict[str, str],
                                 output_dir: str,
                                 result: WikiResult) -> List[str]:
        """生成所有 Wiki 文档

        顺序优化：先逐模块 → 再合并产出跨模块文档
        每篇文档生成后执行 cite-verify，未通过的再由 LLM 修复
        """
        docs = []
        style = result.wiki_style
        cite_warnings: List[str] = []

        project_summary = self._build_project_summary(project_name, modules, descriptions)

        # =============================================================
        # 第一轮：逐模块文档（MODULES/*.md）
        # =============================================================
        module_docs = self._generate_module_docs(modules, descriptions, output_dir, style, meta)
        docs.extend(module_docs)
        result.module_count = len(module_docs)

        # cite-verify 模块文档
        for doc_path in module_docs:
            doc_name = os.path.basename(doc_path)
            try:
                content = open(doc_path, encoding="utf-8").read()
            except Exception:
                continue
            uv = self._cite_verify(content, meta, doc_name)
            if uv:
                fixed = self._cite_fix(content, doc_name, uv, meta)
                if fixed and len(fixed) > 100:
                    with open(doc_path, "w", encoding="utf-8") as f:
                        f.write(fixed)
                cite_warnings.append(f"- {doc_name}: 修复了 {len(uv)} 个未验证标识符: {', '.join(uv[:8])}")

        # =============================================================
        # 第二轮：跨模块文档（README、ARCHITECTURE 等）
        # =============================================================

        # 1. README.md（元数据作为事实源，描述作为风格参考）
        readme = self._generate_readme(project_name, project_summary, modules, style,
                                       descriptions, meta)
        uv = self._cite_verify(readme, meta, "README.md")
        if uv:
            readme = self._cite_fix(readme, "README.md", uv, meta)
            cite_warnings.append(f"- README.md: 修复了 {len(uv)} 个未验证标识符: {', '.join(uv[:8])}")
        docs.append(self._write_doc(output_dir, "README.md", readme))

        # 2. ARCHITECTURE.md
        arch = self._generate_architecture(project_name, project_summary, modules, style,
                                           descriptions, meta)
        uv = self._cite_verify(arch, meta, "ARCHITECTURE.md")
        if uv:
            arch = self._cite_fix(arch, "ARCHITECTURE.md", uv, meta)
            cite_warnings.append(f"- ARCHITECTURE.md: 修复了 {len(uv)} 个未验证标识符: {', '.join(uv[:8])}")
        docs.append(self._write_doc(output_dir, "ARCHITECTURE.md", arch))

        # 3. INSTALLATION.md
        install = self._generate_installation(project_name, project_summary, modules, style, meta)
        uv = self._cite_verify(install, meta, "INSTALLATION.md")
        if uv:
            install = self._cite_fix(install, "INSTALLATION.md", uv, meta)
            cite_warnings.append(f"- INSTALLATION.md: 修复了 {len(uv)} 个未验证标识符")
        docs.append(self._write_doc(output_dir, "INSTALLATION.md", install))

        # 4. USAGE.md
        usage = self._generate_usage(project_name, project_summary, modules, style,
                                     descriptions, meta)
        uv = self._cite_verify(usage, meta, "USAGE.md")
        if uv:
            usage = self._cite_fix(usage, "USAGE.md", uv, meta)
            cite_warnings.append(f"- USAGE.md: 修复了 {len(uv)} 个未验证标识符")
        docs.append(self._write_doc(output_dir, "USAGE.md", usage))

        # 5. API.md (如果有 Web 框架)
        if meta.has_web_framework:
            api = self._generate_api_doc(project_name, project_summary, modules, style, meta)
            uv = self._cite_verify(api, meta, "API.md")
            if uv:
                api = self._cite_fix(api, "API.md", uv, meta)
                cite_warnings.append(f"- API.md: 修复了 {len(uv)} 个未验证标识符")
            docs.append(self._write_doc(output_dir, "API.md", api))

        # 6. WIKI_INDEX.md（纯模板，无需 cite-verify）
        index = self._build_wiki_index(project_name, modules, docs, result)
        docs.append(self._write_doc(output_dir, "WIKI_INDEX.md", index))

        # 记录编校警告到 result
        if cite_warnings:
            result.errors.extend(cite_warnings)

        return docs

    def _build_project_summary(self, project_name: str, modules: List[WikiModule],
                                summaries: Dict[str, str]) -> str:
        """构建项目摘要文本"""
        lines = [
            f"# 项目: {project_name}",
            f"",
            f"## 模块列表",
            f"",
        ]
        for mod in modules:
            core_tag = " [核心]" if mod.is_core else ""
            lines.append(f"- **{mod.name}**{core_tag}: {mod.file_count} 个文件")
        lines.append("")
        lines.append("## 代码摘要")
        lines.append("")

        # 限制总长度
        total_chars = sum(len(l) for l in lines)
        for mod_name, summary in summaries.items():
            if total_chars + len(summary) > self.MAX_CONTEXT_CHARS:
                lines.append(f"\n*(模块 {mod_name} 的摘要已省略，总共 {len(modules)} 个模块)*\n")
                break
            lines.append(summary)
            lines.append("")
            total_chars += len(summary)

        return "\n".join(lines)

    def _llm_ask(self, system_prompt: str, user_prompt: str) -> str:
        """调用 LLM 生成内容"""
        try:
            messages = [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ]
            return self.llm.chat_completion(messages, max_tokens=4096, temperature=0.3)
        except Exception as e:
            return f"*(LLM 生成失败: {str(e)})*"

    def _style_guidelines(self, style: str) -> str:
        """根据 Wiki 风格返回写作指引"""
        guidelines = {
            "comprehensive": (
                "目标读者是不懂代码的用户（老板、同事、客户），用通俗语言解释。"
                "内容要详细全面，不遗漏任何重要信息。"
            ),
            "reference": (
                "目标读者是有经验的开发者。内容精简，直接给出关键信息，"
                "不做过多的背景解释。使用表格和列表组织信息，方便快速查阅。"
            ),
            "tutorial": (
                "目标读者是新手。采用教程风格，逐步引导，每一步都解释清楚。"
                "可以包含「学习目标」「前置知识」「实践练习」等环节。"
            ),
            "plain": (
                "极简风格。只保留核心要点，用最简洁的语言描述。"
                "避免任何修饰性文字，每个模块不超过 3-5 句话。"
            ),
        }
        return guidelines.get(style, guidelines["comprehensive"])

    # ─── 各文档生成 ───

    def _make_fact_constraint(self) -> str:
        """返回事实约束段落，插入到所有 LLM prompt 中，强制基于代码分析结果如实描述"""
        return (
            "⚠️ 事实约束（必须遵守）：\n"
            "1. 本项目是一个目录，包含多个独立的工具/模块，它们可能互不关联，不要编造成一个统一产品。\n"
            "2. 你所写的一切内容必须基于下方「项目分析结果」中的代码分析数据，不得自创概念、虚构功能。\n"
            "3. 描述模块时，直接引用分析结果中出现的类名、函数名、依赖库。\n"
            "4. 如果分析结果显示模块之间没有依赖关系，就说它们独立工作。\n"
            "5. 不要使用「平台」「系统」「架构分层」「数据流」等暗示统一产品的词语，除非分析结果证据确凿。\n"
            "6. 宁可保守（如实列出文件），不要夸张（编造模块间协作关系）。\n"
        )

    def _generate_readme(self, project_name: str, summary: str,
                          modules: List[WikiModule], style: str = "comprehensive",
                          descriptions: Dict[str, str] = None,
                          meta: ProjectCodeMetadata = None) -> str:
        """生成 README.md（元数据为事实源，描述为风格参考）"""
        guidelines = self._style_guidelines(style)
        constraint = self._make_fact_constraint()
        desc_text = self._summarize_descriptions(descriptions or {})
        fact_data = self._make_arch_overview(meta, descriptions or {}) if meta else desc_text
        system_prompt = (
            f"你是一个技术文档撰写专家。编写 README。"
            f"{guidelines}"
            "输出纯 Markdown。\n\n"
            "⚠️ 写作规则：\n"
            "1. 所有类名、函数名、文件名必须来自下方「事实数据」，不得编造。\n"
            "2. 模块描述仅作为理解模块用途的参考，具体标识符以事实数据为准。\n"
            "3. 不要使用「平台」「系统」「引擎」等暗示统一产品的词语。"
        )
        user_prompt = (
            f"请为目录 **{project_name}** 编写 README.md 文档。\n\n"
            f"{constraint}\n"
            f"Wiki 风格: {style} ({self.WIKI_STYLES.get(style, '')})\n\n"
            f"要求：\n"
            f"1. 目录概述：一句话说明这个目录下放了哪些内容\n"
            f"2. 各模块：列出每个模块的名称和功能描述\n"
            f"3. 安装运行：如果事实数据中有入口文件（main.py/app.py），给出运行方式\n"
            f"4. 目录结构：列出实际目录名\n"
            f"5. 文档导航：链接到 docs/wiki/ 下的其他文档\n\n"
            f"=== 事实数据（以此为唯一准确来源）===\n{fact_data[:15000]}\n\n"
            f"=== 模块描述（风格参考，标识符以事实数据为准）===\n{desc_text[:15000]}"
        )
        return self._llm_ask(system_prompt, user_prompt)

    def _generate_architecture(self, project_name: str, summary: str,
                                modules: List[WikiModule], style: str = "comprehensive",
                                descriptions: Dict[str, str] = None,
                                meta: ProjectCodeMetadata = None) -> str:
        """生成 ARCHITECTURE.md（使用全量元数据）"""
        guidelines = self._style_guidelines(style)
        constraint = self._make_fact_constraint()
        # 从 meta 构建结构概览
        arch_meta = self._make_arch_overview(meta, descriptions or {})
        system_prompt = (
            f"你是一个技术文档专家。请基于下方实际代码结构数据，如实描述各个模块。"
            f"{guidelines}"
            "输出纯 Markdown。"
        )
        user_prompt = (
            f"请为目录 **{project_name}** 编写模块结构文档。\n\n"
            f"{constraint}\n"
            f"Wiki 风格: {style} ({self.WIKI_STYLES.get(style, '')})\n\n"
            f"要求：\n"
            f"1. 模块清单：列出每个目录及其中检测到的文件\n"
            f"2. 技术栈：只列出实际出现的库\n"
            f"3. 依赖关系：只列出现有的 import 依赖\n\n"
            f"以下是代码结构数据：\n\n{arch_meta[:30000]}"
        )
        return self._llm_ask(system_prompt, user_prompt)

    def _generate_installation(self, project_name: str, summary: str,
                                modules: List[WikiModule], style: str = "comprehensive",
                                meta: ProjectCodeMetadata = None) -> str:
        """生成 INSTALLATION.md"""
        guidelines = self._style_guidelines(style)
        constraint = self._make_fact_constraint()
        deps_info = self._extract_deps_info(summary)
        fact_data = self._make_arch_overview(meta, {}) if meta else summary
        system_prompt = (
            f"你是一个技术文档撰写专家。如实编写安装指南。"
            f"{guidelines}"
            "输出纯 Markdown。\n\n"
            "⚠️ 所有依赖库、文件名必须来自下方事实数据。"
        )
        user_prompt = (
            f"请为目录 **{project_name}** 编写 INSTALLATION.md 安装指南。\n\n"
            f"{constraint}\n"
            f"Wiki 风格: {style} ({self.WIKI_STYLES.get(style, '')})\n\n"
            f"要求：\n"
            f"1. 环境要求：只列事实数据中检测到的 requirements.txt / pyproject.toml 内容\n"
            f"2. 依赖安装：只列事实数据中出现的依赖库\n"
            f"3. 配置步骤：只列事实数据中检测到的 config 文件\n"
            f"4. 验证安装：只列事实数据中的入口文件\n\n"
            f"=== 事实数据 ===\n{fact_data[:15000]}\n\n"
            f"依赖信息：{deps_info}"
        )
        return self._llm_ask(system_prompt, user_prompt)

    def _generate_usage(self, project_name: str, summary: str,
                         modules: List[WikiModule], style: str = "comprehensive",
                         descriptions: Dict[str, str] = None,
                         meta: ProjectCodeMetadata = None) -> str:
        """生成 USAGE.md"""
        guidelines = self._style_guidelines(style)
        constraint = self._make_fact_constraint()
        desc_text = self._summarize_descriptions(descriptions or {})
        fact_data = self._make_arch_overview(meta, descriptions or {}) if meta else desc_text
        system_prompt = (
            f"你是一个技术文档撰写专家。如实编写使用说明。"
            f"{guidelines}"
            "输出纯 Markdown。\n\n"
            "⚠️ 所有入口文件、函数名必须来自下方事实数据。"
        )
        user_prompt = (
            f"请为目录 **{project_name}** 编写 USAGE.md 使用说明。\n\n"
            f"{constraint}\n"
            f"Wiki 风格: {style} ({self.WIKI_STYLES.get(style, '')})\n\n"
            f"要求：\n"
            f"1. 运行方式：只列事实数据中的 main.py/app.py/server.py 入口\n"
            f"2. 每个模块用法：基于模块描述说明用途，但入口函数以事实数据为准\n"
            f"3. 入口文件：列出事实数据中检测到的入口文件\n\n"
            f"=== 事实数据（标识符以此为唯一来源）===\n{fact_data[:15000]}\n\n"
            f"=== 模块描述（风格参考）===\n{desc_text[:15000]}"
        )
        return self._llm_ask(system_prompt, user_prompt)

    def _generate_module_docs(self, modules: List[WikiModule],
                               descriptions: Dict[str, str],
                               output_dir: str, style: str = "comprehensive",
                               meta: ProjectCodeMetadata = None) -> List[str]:
        """生成 MODULES/ 目录下的模块文档"""
        docs = []
        modules_dir = os.path.join(output_dir, "MODULES")
        guidelines = self._style_guidelines(style)
        constraint = self._make_fact_constraint()

        index = self._build_module_index(modules)
        docs.append(self._write_doc(modules_dir, "_index.md", index))

        # 为每个核心模块生成详细文档
        for mod in modules:
            if not mod.is_core:
                continue
            desc = descriptions.get(mod.name, "")
            if not desc:
                continue

            # 从 meta 提取该模块的事实数据
            mod_meta_text = ""
            if meta:
                for mm in meta.modules:
                    if mm.name == mod.name:
                        mod_meta_text = self._module_metadata_to_text(mm)
                        break

            system_prompt = (
                f"你是一个技术文档撰写专家。如实编写模块文档。"
                f"{guidelines}"
                "输出纯 Markdown。\n\n"
                "⚠️ 所有类名、函数名、文件名必须来自下方事实数据。"
            )
            user_prompt = (
                f"请为目录下的 **{mod.name}** 模块编写文档。\n\n"
                f"{constraint}\n"
                f"Wiki 风格: {style} ({self.WIKI_STYLES.get(style, '')})\n\n"
                f"要求：\n"
                f"1. 模块内容：只列事实数据中检测到的文件\n"
                f"2. 类与函数：只列事实数据中出现的类和函数\n"
                f"3. 依赖关系：只列事实数据中的依赖\n"
                f"4. 使用方式：如果有入口文件说明如何运行\n\n"
                f"=== 事实数据（以此为唯一准确来源）===\n{mod_meta_text[:15000] if mod_meta_text else ''}\n\n"
                f"=== 模块描述（风格参考）===\n{desc[:10000]}"
            )
            content = self._llm_ask(system_prompt, user_prompt)
            docs.append(self._write_doc(modules_dir, f"{mod.name}.md", content))

        return docs

    def _build_module_index(self, modules: List[WikiModule]) -> str:
        """生成模块索引"""
        lines = [
            f"# 模块索引",
            f"",
            f"| 模块 | 文件数 | 类型 | 文档 |",
            f"|------|--------|------|------|",
        ]
        for mod in modules:
            core_tag = "核心" if mod.is_core else "辅助"
            doc_link = f"[查看]({mod.name}.md)" if mod.is_core else "-"
            lines.append(f"| {mod.name} | {mod.file_count} | {core_tag} | {doc_link} |")
        return "\n".join(lines)

    def _summarize_descriptions(self, descriptions: Dict[str, str]) -> str:
        """将 Stage 2 模块描述转为紧凑文本"""
        lines = []
        for mod_name, desc in descriptions.items():
            lines.append(f"## {mod_name}")
            lines.append(desc[:1500])  # 每个模块描述截断以防超长
            lines.append("")
        return "\n".join(lines)

    def _make_arch_overview(self, meta: ProjectCodeMetadata,
                            descriptions: Dict[str, str]) -> str:
        """从元数据构建架构概览"""
        lines = [f"总文件数: {meta.total_files if meta else '?'}"]
        lines.append(f"模块数: {len(meta.modules) if meta else '?'}")
        lines.append(f"Web框架: {'检测到' if meta and meta.has_web_framework else '未检测到'}")
        lines.append("")
        if meta:
            for mod in meta.modules:
                entry_files = [f.rel_path for f in mod.files if f.is_entry_point]
                lines.append(f"### {mod.name} ({mod.total_files} 文件)")
                if entry_files:
                    lines.append(f"入口: {', '.join(entry_files)}")
                # 所有文件的类/函数摘要
                all_classes = []
                all_funcs = []
                all_imports = set()
                for f in mod.files:
                    for c in f.classes:
                        all_classes.append(c["name"])
                    for fn in f.functions:
                        all_funcs.append(fn["name"])
                    for imp in f.imports:
                        all_imports.add(imp)
                if all_classes:
                    lines.append(f"类: {', '.join(all_classes[:10])}")
                if all_funcs:
                    lines.append(f"函数: {', '.join(all_funcs[:10])}")
                if all_imports:
                    lines.append(f"依赖: {', '.join(sorted(all_imports)[:15])}")
                lines.append("")
        return "\n".join(lines)

    def _make_web_info(self, meta: ProjectCodeMetadata) -> str:
        """从元数据提取 Web 框架信息"""
        if not meta or not meta.has_web_framework:
            return "未检测到 Web 框架。"
        lines = ["检测到 Web 框架。以下文件可能包含路由/端点："]
        for mod in meta.modules:
            for f in mod.files:
                if any(imp.lower() in {"fastapi", "flask", "django", "aiohttp",
                                       "starlette", "apirouter"} for imp in f.imports):
                    lines.append(f"  - {mod.name}/{f.rel_path}")
                    for c in f.classes:
                        lines.append(f"    class {c['name']}")
                    for fn in f.functions:
                        lines.append(f"    def {fn['name']}()")
        return "\n".join(lines)

    # ═══════════════════════════════════════════════════════════════════
    # 编校验证：从生成文本提取标识符，与 Stage 1 元数据交叉核对
    # ═══════════════════════════════════════════════════════════════════

    # 标识符提取时忽略的常见词
    CITE_IGNORE = {
        "pip", "bash", "json", "txt", "yaml", "html", "css", "md",
        "exe", "com", "org", "url", "http", "https", "api", "rest",
        "utf", "utf-8", "ascii", "base64", "sha256", "md5",
        "true", "false", "none", "null", "yes", "no",
        "localhost", "0.0.0.0", "127.0.0.1", "v1", "v2", "v3",
        "chcp", "nul", "goto", "set", "echo", "rem", "pause",
        "cli", "gui", "sdk", "ide", "db", "sql", "nosql",
        "linux", "macos", "windows", "ios", "android",
        "readme", "license", "gitignore",
        "post-commit", "pre-commit", "commit-msg",
        "node_modules", "pycache", "venv", "env",
    }

    def _cite_verify(self, text: str, meta: ProjectCodeMetadata,
                     doc_name: str) -> List[str]:
        """从生成的文本中提取反引号标识符，与元数据交叉核对

        Returns:
            未在元数据中验证通过的标识符列表
        """
        if not meta:
            return []

        # 1. 提取所有反引号片段
        tokens = set()
        for m in re.finditer(r'`([^`]+)`', text):
            token = m.group(1).strip()
            # 过滤：太短、太长、含空格、换行、纯数字
            if len(token) < 2 or len(token) > 80:
                continue
            if ' ' in token or '\n' in token:
                continue
            if token.isdigit():
                continue
            # 过滤含中文的文本（代码标识符不含中文）
            if re.search(r'[\u4e00-\u9fff]', token):
                continue
            # 过滤纯标点或纯符号
            if re.match(r'^[^\w]+$', token):
                continue
            tokens.add(token)

        # 2. 收集元数据中所有已知标识符
        known = set()
        # 类名 + 方法名
        for mod in meta.modules:
            for f in mod.files:
                for c in f.classes:
                    known.add(c["name"])
                    for m in c.get("methods", []):
                        known.add(m)
        # 函数名
        for mod in meta.modules:
            for f in mod.files:
                for fn in f.functions:
                    known.add(fn["name"])
        # 文件名（含正反斜杠两种路径格式）
        for mod in meta.modules:
            for f in mod.files:
                known.add(f.rel_path)
                known.add(f.rel_path.replace("\\", "/"))
                known.add(f.rel_path.replace("/", "\\"))
                known.add(os.path.basename(f.rel_path))
        # 目录名
        for mod in meta.modules:
            for f in mod.files:
                d = os.path.dirname(f.rel_path)
                if d and d != ".":
                    known.add(d)
                    known.add(d.replace("\\", "/"))
        # 依赖库名
        for mod in meta.modules:
            for f in mod.files:
                for imp in f.imports:
                    known.add(imp)
        # 模块名
        for mod in meta.modules:
            known.add(mod.name)
        # 项目名
        known.add(os.path.basename(meta.project_path))

        # 小写化用于忽略大小写匹配
        known_lower = {k.lower() for k in known}

        # 3. 校验
        unverified = []
        for token in sorted(tokens):
            # 标准化：去拖尾斜杠，连字符转下划线
            t = token.rstrip("/").rstrip("\\")
            t = t.replace("-", "_")
            if t.lower() in self.CITE_IGNORE:
                continue
            if t.lower() in known_lower:
                continue
            # 去掉 .py / .json 等后缀再试
            base = re.sub(r'\.(py|json|yaml|yml|toml|cfg|ini|md|txt|html|css|js|ts)$', '', t)
            if base.lower() in known_lower:
                continue
            # 去掉可能的 () 后缀（函数调用）
            base2 = re.sub(r'\(.*\)$', '', t)
            if base2.lower() in known_lower:
                continue
            unverified.append(token)

        if unverified:
            print(f"[cite-verify] {doc_name}: {len(unverified)} 个未验证标识符: {unverified[:20]}")

        return unverified

    def _cite_fix(self, doc_text: str, doc_name: str, unverified: List[str],
                   meta: ProjectCodeMetadata) -> str:
        """让 LLM 根据校验结果修复文档段落"""
        if not unverified:
            return doc_text

        system_prompt = (
            "你是一个文档校对专家。你的任务是修正下文中出现的代码标识符错误。\n"
            "以下标识符在代码中不存在，请将它们替换为文中合理且实际存在的名称，"
            "或删除含这些标识符的句子。\n"
            "不要改变文章的整体结构和写作风格。\n"
            "输出修正后的全文。"
        )
        user_prompt = (
            f"文档: {doc_name}\n\n"
            f"不存在的标识符 ({len(unverified)} 个): {', '.join(unverified[:20])}\n"
            f"{'...' if len(unverified) > 20 else ''}\n\n"
            f"原文:\n```\n{doc_text[:30000]}\n```\n\n"
            f"请修正后输出全文。"
        )
        fixed = self._llm_ask(system_prompt, user_prompt)
        return fixed if fixed and len(fixed) > 100 else doc_text

    def _generate_api_doc(self, project_name: str, summary: str,
                           modules: List[WikiModule], style: str = "comprehensive",
                           meta: ProjectCodeMetadata = None) -> str:
        """生成 API.md（Web 框架专用）"""
        guidelines = self._style_guidelines(style)
        constraint = self._make_fact_constraint()
        web_info = self._make_web_info(meta)
        system_prompt = (
            f"你是一个 API 文档撰写专家。如实编写 API 文档。"
            f"{guidelines}"
            "输出纯 Markdown。\n\n"
            "⚠️ 所有端点、路由、参数必须来自下方事实数据，不得编造。"
        )
        user_prompt = (
            f"请为目录 **{project_name}** 编写 API.md 文档。\n\n"
            f"{constraint}\n"
            f"Wiki 风格: {style} ({self.WIKI_STYLES.get(style, '')})\n\n"
            f"要求：\n"
            f"1. 只列事实数据中检测到的 Web 框架文件和其中定义的类/函数\n"
            f"2. 每个文件路径如实写明\n"
            f"3. 如果没有检测到路由信息，直接写「未检测到 API 端点」\n\n"
            f"=== 事实数据 ===\n{web_info[:15000]}"
        )
        return self._llm_ask(system_prompt, user_prompt)

    def _build_wiki_index(self, project_name: str, modules: List[WikiModule],
                            docs: List[str], result: WikiResult) -> str:
        """生成 WIKI_INDEX.md（导航首页）"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        large_tag = " (大仓库采样模式)" if result.large_repo else ""
        style_tag = f" [{result.wiki_style} 风格]"

        lines = [
            f"# {project_name} — 项目 Wiki",
            f"",
            f"> 自动生成于 {now}{large_tag}{style_tag}",
            f"> 由 CodeRef Wiki Generator 驱动",
            f"",
            f"## 导航",
            f"",
            f"| 文档 | 内容 | 适合谁 |",
            f"|------|------|--------|",
            f"| [📖 README](README.md) | 项目概述、快速开始 | 所有人 |",
            f"| [🏗️ 架构设计](ARCHITECTURE.md) | 系统架构、模块关系 | 开发者 |",
            f"| [📦 安装指南](INSTALLATION.md) | 手把手安装教程 | 新用户 |",
            f"| [📘 使用指南](USAGE.md) | 功能使用说明 | 用户 |",
            f"| [📂 模块索引](MODULES/_index.md) | 模块列表和文档 | 开发者 |",
        ]

        if any("API.md" in d for d in docs):
            lines.append(f"| [🔌 API 文档](API.md) | API 端点说明 | 开发者 |")

        lines.append("")
        lines.append(f"## 模块概览")
        lines.append("")
        for mod in modules:
            core_tag = " 🔑" if mod.is_core else ""
            lines.append(f"- **{mod.name}**{core_tag} — {mod.file_count} 个文件")

        # 子项目导航
        if result.subprojects:
            lines.append("")
            lines.append("## 子项目 Wiki")
            lines.append("")
            for sp in result.subproject_results:
                sp_name = sp["name"]
                sp_docs = sp["documents"]
                sp_files = sp["total_files"]
                sp_large = " ⚠️" if sp["large_repo"] else ""
                lines.append(f"- [{sp_name}](subprojects/{sp_name}/WIKI_INDEX.md) — {sp_files} 个文件, {sp_docs} 个文档{sp_large}")

        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("### 关于本 Wiki")
        lines.append("")
        lines.append("本 Wiki 由 CodeRef AI 自动生成，使用 LLM 理解代码语义后撰写。")
        lines.append("如果你修改了代码，可以重新运行 `coderef_generate_wiki` 更新文档。")
        lines.append("")
        if result.large_repo:
            lines.append("⚠️ 本项目文件较多，Wiki 采用采样模式生成。如需完整文档，请在较小批次中分批生成。")
        lines.append("")

        return "\n".join(lines)

    # ─── 辅助方法 ───

    def _extract_deps_info(self, summary: str) -> str:
        """从摘要中提取依赖信息"""
        # 搜索 "依赖:" 行
        deps = re.findall(r'\*\*依赖\*\*:\s*(.+)', summary)
        if deps:
            return "\n".join(deps[:5])
        return "未找到明确的依赖信息"

    def _write_doc(self, output_dir: str, filename: str, content: str) -> str:
        """写入文档文件"""
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return filepath

    # ─── Git Hook 配置 ───

    def _setup_git_hook(self, project_path: str, output_dir: str):
        """安装 git post-commit hook 自动更新 wiki"""
        git_dir = os.path.join(project_path, ".git")
        if not os.path.isdir(git_dir):
            return

        hooks_dir = os.path.join(git_dir, "hooks")
        os.makedirs(hooks_dir, exist_ok=True)

        hook_path = os.path.join(hooks_dir, "post-commit")
        hook_script = f'''#!/bin/bash
# CodeRef Wiki Auto-Update Hook
# 每次 git commit 后自动更新项目 Wiki
# 安装方式: coderef_generate_wiki --enable-git-hook

echo "[CodeRef] 正在更新项目 Wiki..."

# 找到 CodeRef 的安装路径
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# 调用 CodeRef MCP 更新 Wiki
python -m core.mcp_server --tool generate_wiki --project "$PROJECT_ROOT" --output "{output_dir}" 2>/dev/null

echo "[CodeRef] Wiki 已更新"
'''

        try:
            with open(hook_path, "w", encoding="utf-8") as f:
                f.write(hook_script)
            # 设置可执行权限
            os.chmod(hook_path, 0o755)
        except (OSError, IOError):
            pass  # 非阻塞，失败了不影响主流程

    # ─── 报告生成 ───

    def to_report(self, result: WikiResult) -> str:
        """生成 Markdown 格式的生成报告"""
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        lines = [
            f"# Wiki 生成报告",
            f"",
            f"> 项目: `{result.project_path}`",
            f"> 项目名称: **{result.project_name}**",
            f"> 生成时间: {now}",
            f"> Wiki 风格: **{result.wiki_style}** ({self.WIKI_STYLES.get(result.wiki_style, '')})",
            f"> 总文件数: {result.total_files}",
        ]

        if result.large_repo:
            lines.append(f"> ⚠️ 大仓库模式：文件数超过 {self.LARGE_REPO_THRESHOLD}，采用采样分析")

        lines.append("")
        lines.append("## 生成的文档")
        lines.append("")

        for doc in result.documents:
            rel = os.path.relpath(doc, result.output_dir)
            lines.append(f"- [{rel}]({rel})")

        # 子项目信息
        if result.subprojects:
            lines.append("")
            lines.append("## 发现子项目")
            lines.append("")
            for sp in result.subproject_results:
                sp_name = sp["name"]
                sp_count = sp["documents"]
                sp_files = sp["total_files"]
                lines.append(f"- **{sp_name}**: {sp_files} 个文件 → {sp_count} 个文档 (在 `subprojects/{sp_name}/`)")

        lines.append("")
        lines.append(f"## 统计")
        lines.append("")
        lines.append(f"| 指标 | 数值 |")
        lines.append(f"|------|------|")
        lines.append(f"| 文档总数 | {len(result.documents)} |")
        lines.append(f"| 模块文档 | {result.module_count} |")
        lines.append(f"| 总文件数 | {result.total_files} |")
        lines.append(f"| Wiki 风格 | {result.wiki_style} |")
        lines.append(f"| 大仓库模式 | {'是' if result.large_repo else '否'} |")
        lines.append(f"| 子项目数 | {len(result.subprojects)} |")

        if result.errors:
            lines.append("")
            lines.append("## 警告")
            for e in result.errors:
                lines.append(f"- {e}")

        lines.append("")
        lines.append("---")
        lines.append(f"*由 CodeRef Wiki Generator v2.0 生成*")

        return "\n".join(lines)