# -*- coding: utf-8 -*-
"""
垃圾文件检测器 —— 检测项目中的无用文件，帮助不懂代码的用户清理项目

检测维度：
1. __pycache__ 目录和 .pyc 编译缓存文件
2. 重复/高度相似的文件（基于文件大小 + 前 100 行哈希，相似度 > 90%）
3. 0 字节空文件
4. 只有注释和 import 没有实际代码的空壳文件
5. 应该被 .gitignore 但没被忽略的文件（.pyc、.log、.env、.DS_Store 等）
6. 超过 30 天未修改的孤立文件（不在任何 import 链中）

输出：Markdown 报告，包含垃圾总览、分类清单、清理建议（安全/需确认）、
以及面向不懂代码的用户的通俗解释。

与 CodeSimplifier / GovernanceAuditor 的关系：
- CodeSimplifier 聚焦代码精简（YAGNI、死代码、过度工程）
- GovernanceAuditor 聚焦安全与架构合规
- JunkDetector 聚焦项目中的垃圾文件清理（面向非技术用户）

作者: PersuadeAI Team
版本: v1.0
"""

import os
import re
import hashlib
import difflib
from datetime import datetime, timedelta
from typing import Dict, List, Set, Tuple, Optional
from dataclasses import dataclass, field
from collections import defaultdict

from loguru import logger
from core.shared_filter import SharedFilter


# ═══════════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════════

@dataclass
class JunkItem:
    """
    单条垃圾文件记录

    Attributes:
        category: 分类（pycache / duplicate / zero_byte / empty_shell /
                  ungitignored / orphan）
        file_path: 文件路径
        size_bytes: 文件大小（字节）
        reason: 判定为垃圾的原因（面向不懂代码的用户的通俗解释）
        safe_to_delete: 是否可安全删除（True=放心删，False=需确认）
    """
    category: str
    file_path: str
    size_bytes: int
    reason: str
    safe_to_delete: bool = True

    def to_dict(self) -> Dict:
        return {
            "category": self.category,
            "file_path": self.file_path,
            "size_bytes": self.size_bytes,
            "reason": self.reason,
            "safe_to_delete": self.safe_to_delete,
        }


# ═══════════════════════════════════════════════════════════════════
# 分类标签与说明
# ═══════════════════════════════════════════════════════════════════

CATEGORY_LABELS = {
    "pycache": "Python 编译缓存",
    "duplicate": "重复/高度相似文件",
    "zero_byte": "0 字节空文件",
    "empty_shell": "空壳文件（无实际代码）",
    "ungitignored": "应被忽略但未忽略的文件",
    "orphan": "孤立文件（长期未修改且未被引用）",
}

CATEGORY_EXPLANATIONS = {
    "pycache": (
        "Python 运行时会自动生成 `.pyc` 编译缓存文件，存放在 `__pycache__` 目录中。"
        "这些文件是 Python 为了提高下次运行速度而自动创建的，删除后 Python 会在下次运行时自动重新生成。"
        "**完全安全，可以放心删除。**"
    ),
    "duplicate": (
        "项目中存在内容高度相似（>90%）的重复文件。这些文件可能是复制粘贴产生的副本，"
        "保留多份相同内容不仅浪费空间，还会让项目变得混乱。"
        "**建议确认后，只保留其中一份，删除其余副本。**"
    ),
    "zero_byte": (
        "文件大小为 0 字节，即完全空白的文件。这些文件不包含任何内容，"
        "通常是误创建或程序异常退出留下的。"
        "**可以安全删除，但建议先确认文件名是否是有意保留的占位文件。**"
    ),
    "empty_shell": (
        "文件中只有注释和 import 导入语句，没有任何实际代码（函数、类、逻辑等）。"
        "这类文件通常是 AI 编程工具自动生成的模板，但从未被真正使用。"
        "**建议确认后删除。**"
    ),
    "ungitignored": (
        "这些文件类型（如 `.pyc`、`.log`、`.env`、`.DS_Store` 等）通常应该被 "
        "`.gitignore` 忽略，但当前项目的 `.gitignore` 没有配置忽略规则，"
        "或者这些文件在 `.gitignore` 配置之前就已经被 Git 追踪了。"
        "**建议更新 `.gitignore` 文件，加入忽略规则。**"
    ),
    "orphan": (
        "这些文件超过 30 天没有被修改过，且没有任何其他代码文件引用它们（import）。"
        "它们很可能是被遗忘的、不再需要的文件。"
        "**建议确认后删除，如果确实不再需要的话。**"
    ),
}

# 应该被 .gitignore 忽略的文件模式
SHOULD_BE_IGNORED_PATTERNS = [
    (r'\.pyc$', "Python 编译缓存文件"),
    (r'\.pyo$', "Python 优化编译文件"),
    (r'__pycache__', "Python 缓存目录"),
    (r'\.log$', "日志文件"),
    (r'\.env$', "环境变量文件（可能含敏感信息）"),
    (r'\.env\.\w+$', "环境变量文件"),
    (r'\.DS_Store$', "macOS 系统文件"),
    (r'Thumbs\.db$', "Windows 缩略图缓存"),
    (r'\.idea/', "JetBrains IDE 配置"),
    (r'\.vscode/', "VS Code 配置"),
    (r'\.pytest_cache', "pytest 缓存"),
    (r'\.mypy_cache', "mypy 类型检查缓存"),
    (r'\.ruff_cache', "ruff 代码检查缓存"),
    (r'node_modules/', "Node.js 依赖（通常应被忽略）"),
    (r'\.egg-info/', "Python 打包信息"),
    (r'dist/', "Python 构建产物"),
    (r'build/', "构建产物目录"),
    (r'\.coverage$', "测试覆盖率文件"),
    (r'\.tox/', "tox 测试环境"),
]


# ═══════════════════════════════════════════════════════════════════
# 垃圾检测器
# ═══════════════════════════════════════════════════════════════════

class JunkDetector:
    """
    垃圾文件检测器

    扫描项目目录，检测 6 类垃圾文件，生成 Markdown 报告。
    报告面向不懂代码的用户，使用通俗语言解释每类垃圾是什么、为什么可以删除。

    用法:
        detector = JunkDetector()
        report = detector.detect("/path/to/project")
        print(report)
    """

    # 扫描时忽略的目录名
    IGNORE_DIRS = {
        ".git", ".svn", ".hg",           # 版本控制
        ".pytest_cache", ".mypy_cache",   # 工具缓存
        ".ruff_cache", ".tox",
        "node_modules",                    # 依赖目录
        ".venv", "venv", "env", ".env",   # 虚拟环境
        "dist", "build", "egg-info",      # 构建产物
    }

    def __init__(self):
        self._items: List[JunkItem] = []

    def detect(self, project_path: str) -> str:
        """
        执行垃圾文件检测并生成报告

        Args:
            project_path: 项目根目录路径

        Returns:
            Markdown 格式的垃圾检测报告
        """
        logger.info(f"[JunkDetector] 开始扫描: {project_path}")

        # 加载项目专属的 cache 硬编码优化（白名单）
        SharedFilter.load_cache(project_path)

        from core.project_scope import ProjectScope
        self._scope = ProjectScope(project_path)
        self._scope.analyze()

        self._items = []

        # 1. 扫描 __pycache__ 和 .pyc 文件
        self._scan_pycache(project_path)

        # 2. 检测重复/高度相似文件
        self._detect_duplicates(project_path)

        # 3. 检测 0 字节文件
        self._detect_zero_byte(project_path)

        # 4. 检测空壳文件
        self._detect_empty_shells(project_path)

        # 5. 检测应该被 .gitignore 但没被忽略的文件
        self._detect_ungitignored(project_path)

        # 6. 检测孤立文件
        self._detect_orphans(project_path)

        logger.info(f"[JunkDetector] 扫描完成: 发现 {len(self._items)} 个垃圾项")

        return self._generate_report(project_path)

    # ─── 检测 1: __pycache__ 和 .pyc ───────────────────────────────

    def _scan_pycache(self, project_path: str):
        """扫描 __pycache__ 目录和 .pyc 文件"""
        for root, dirs, files in os.walk(project_path):
            # 使用 ProjectScope 过滤目录
            dirs[:] = [d for d in dirs if self._scope.should_scan(os.path.join(root, d))]

            # 检测 __pycache__ 目录本身
            if os.path.basename(root) == "__pycache__":
                total_size = 0
                pyc_count = 0
                for f in files:
                    fpath = os.path.join(root, f)
                    try:
                        total_size += os.path.getsize(fpath)
                        pyc_count += 1
                    except OSError:
                        pass
                if pyc_count > 0:
                    self._items.append(JunkItem(
                        category="pycache",
                        file_path=root + os.sep,
                        size_bytes=total_size,
                        reason=f"Python 自动生成的编译缓存目录，包含 {pyc_count} 个缓存文件。"
                               f"删除后 Python 会在下次运行时自动重新生成，不会影响程序运行。",
                        safe_to_delete=True,
                    ))
                continue  # 跳过 __pycache__ 内部文件扫描

            # 检测散落的 .pyc 文件（不在 __pycache__ 中的）
            for f in files:
                if f.endswith(".pyc") or f.endswith(".pyo"):
                    fpath = os.path.join(root, f)
                    try:
                        fsize = os.path.getsize(fpath)
                    except OSError:
                        fsize = 0
                    self._items.append(JunkItem(
                        category="pycache",
                        file_path=fpath,
                        size_bytes=fsize,
                        reason="Python 编译缓存文件，不在 __pycache__ 目录中。"
                               "可以安全删除，删除后 Python 会在下次运行时自动重新生成。",
                        safe_to_delete=True,
                    ))

    # ─── 检测 2: 重复/高度相似文件 ─────────────────────────────────

    def _detect_duplicates(self, project_path: str):
        """检测重复/高度相似的文件（基于文件大小 + 前 100 行哈希）"""
        # 按文件大小分组
        size_buckets: Dict[int, List[str]] = defaultdict(list)

        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if self._scope.should_scan(os.path.join(root, d))]
            if os.path.basename(root) == "__pycache__":
                continue
            for f in files:
                if f == "__init__.py":
                    continue  # 跳过包标记文件
                fpath = os.path.join(root, f)
                try:
                    fsize = os.path.getsize(fpath)
                except OSError:
                    continue
                if fsize > 0:
                    size_buckets[fsize].append(fpath)

        # 在相同大小的桶内比较内容
        processed = set()
        for fsize, fpaths in size_buckets.items():
            if len(fpaths) < 2:
                continue
            # 性能保护：单桶超过 200 个文件时跳过 O(n²) 相似度比较
            if len(fpaths) > 200:
                continue

            # 计算每个文件前 100 行的哈希
            file_hashes: Dict[str, List[str]] = defaultdict(list)
            for fpath in fpaths:
                if fpath in processed:
                    continue
                fhash = self._hash_first_lines(fpath, 100)
                file_hashes[fhash].append(fpath)

            # 哈希相同的文件是重复的
            for fhash, dup_paths in file_hashes.items():
                if len(dup_paths) < 2:
                    continue

                # 对于哈希相同但还有更多文件的桶，用相似度做二次确认
                # 哈希相同意味着前 100 行完全一致，直接判为重复
                keep_file = dup_paths[0]  # 建议保留第一个
                for dup_path in dup_paths[1:]:
                    processed.add(dup_path)
                    self._items.append(JunkItem(
                        category="duplicate",
                        file_path=dup_path,
                        size_bytes=fsize,
                        reason=f"与 `{os.path.basename(keep_file)}` 内容高度相似（前 100 行完全一致）。"
                               f"可能是复制粘贴产生的副本，建议只保留一份。",
                        safe_to_delete=False,
                    ))

            # 对于哈希不同但大小相同的文件，用相似度做二次检查
            remaining = [p for p in fpaths if p not in processed]
            # 性能保护：剩余文件 > 200 时跳过 O(n²) 相似度比较
            if len(remaining) > 200:
                continue
            for i, fp1 in enumerate(remaining):
                if fp1 in processed:
                    continue
                for fp2 in remaining[i + 1:]:
                    if fp2 in processed:
                        continue
                    similarity = self._content_similarity(fp1, fp2, max_lines=100)
                    if similarity > 0.90:
                        processed.add(fp2)
                        self._items.append(JunkItem(
                            category="duplicate",
                            file_path=fp2,
                            size_bytes=fsize,
                            reason=f"与 `{os.path.basename(fp1)}` 内容相似度 {similarity:.0%}（>90%）。"
                                   f"可能是复制粘贴产生的副本，建议只保留一份。",
                            safe_to_delete=False,
                        ))

    # ─── 检测 3: 0 字节文件 ────────────────────────────────────────

    def _detect_zero_byte(self, project_path: str):
        """检测 0 字节文件（排除 __init__.py 等占位文件）"""
        placeholders = {"__init__.py", "__init__.pyi", ".gitkeep", ".keep", ".gitignore"}

        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if self._scope.should_scan(os.path.join(root, d))]
            if os.path.basename(root) == "__pycache__":
                continue
            for f in files:
                fpath = os.path.join(root, f)
                try:
                    fsize = os.path.getsize(fpath)
                except OSError:
                    continue
                if fsize == 0 and f not in placeholders:
                    self._items.append(JunkItem(
                        category="zero_byte",
                        file_path=fpath,
                        size_bytes=0,
                        reason="文件内容为空（0 字节），不包含任何信息。"
                               "通常是误创建或程序异常退出留下的。",
                        safe_to_delete=True,
                    ))

    # ─── 检测 4: 空壳文件 ──────────────────────────────────────────

    def _detect_empty_shells(self, project_path: str):
        """检测只有注释和 import 没有实际代码的空壳 .py 文件"""
        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if self._scope.should_scan(os.path.join(root, d))]
            if os.path.basename(root) == "__pycache__":
                continue
            for f in files:
                if not f.endswith(".py"):
                    continue
                fpath = os.path.join(root, f)
                if f == "__init__.py":
                    continue  # 跳过包初始化文件

                try:
                    with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                        content = fh.read()
                except Exception:
                    continue

                if self._is_empty_shell(content):
                    try:
                        fsize = os.path.getsize(fpath)
                    except OSError:
                        fsize = 0
                    self._items.append(JunkItem(
                        category="empty_shell",
                        file_path=fpath,
                        size_bytes=fsize,
                        reason="文件中只有注释和 import 导入语句，没有任何实际的函数、类或逻辑代码。"
                               "这通常是 AI 编程工具自动生成的模板文件，但从未被真正使用。",
                        safe_to_delete=False,
                    ))

    def _is_empty_shell(self, content: str) -> bool:
        """
        判断文件是否为空壳（只有注释、import、文档字符串，没有实际代码）

        实际代码的定义：函数定义(def)、类定义(class)、变量赋值(=)、
        实际调用、装饰器、if/for/while 等控制流语句。
        """
        lines = content.split("\n")
        has_code = False

        for line in lines:
            stripped = line.strip()
            # 跳过空行
            if not stripped:
                continue
            # 跳过注释
            if stripped.startswith("#"):
                continue
            # 跳过文档字符串（单行或多行）
            if stripped.startswith('"""') or stripped.startswith("'''"):
                continue
            if stripped in ('"""', "'''"):
                continue
            # 跳过 import 和 from ... import
            if stripped.startswith("import ") or stripped.startswith("from "):
                continue
            # 跳过 __future__ 导入
            if stripped.startswith("__"):
                # 允许 __all__, __version__, __author__ 等元信息
                if re.match(r'^__\w+__\s*=', stripped):
                    continue
            # 跳过编码声明
            if stripped.startswith("# -*- coding"):
                continue
            # 跳过 #! shebang
            if stripped.startswith("#!"):
                continue
            # 跳过类型提示 only 的赋值（如 x: int）
            if re.match(r'^\w+\s*:\s*\w+(\[\w+\])?\s*$', stripped):
                continue
            # 跳过 pass 语句
            if stripped == "pass":
                continue

            # 如果走到这里，说明有实际代码
            has_code = True
            break

        return not has_code and len(content.strip()) > 0

    # ─── 检测 5: 应被 .gitignore 但未忽略的文件 ─────────────────────

    def _detect_ungitignored(self, project_path: str):
        """检测应该被 .gitignore 但没被忽略的文件"""
        gitignore_path = os.path.join(project_path, ".gitignore")
        ignore_patterns = set()

        if os.path.isfile(gitignore_path):
            try:
                with open(gitignore_path, "r", encoding="utf-8", errors="ignore") as fh:
                    for line in fh:
                        stripped = line.strip()
                        if stripped and not stripped.startswith("#"):
                            ignore_patterns.add(stripped)
            except Exception:
                pass

        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if self._scope.should_scan(os.path.join(root, d))]
            if os.path.basename(root) == "__pycache__":
                # __pycache__ 已在检测 1 中处理，这里只检查 .gitignore 是否覆盖
                if not self._is_ignored_by_patterns("__pycache__/", ignore_patterns):
                    # 只报告一次
                    if not any(item.file_path == root + os.sep and item.category == "ungitignored"
                               for item in self._items):
                        self._items.append(JunkItem(
                            category="ungitignored",
                            file_path=root + os.sep,
                            size_bytes=0,
                            reason="`__pycache__` 目录未被 `.gitignore` 忽略。"
                                   "建议在 `.gitignore` 中添加 `__pycache__/` 规则。",
                            safe_to_delete=False,
                        ))
                continue

            for f in files:
                for pattern, desc in SHOULD_BE_IGNORED_PATTERNS:
                    if re.search(pattern, f) or re.search(pattern, f.replace("\\", "/")):
                        fpath = os.path.join(root, f)
                        # 检查是否已被 .gitignore 覆盖
                        rel_path = os.path.relpath(fpath, project_path).replace("\\", "/")
                        if not self._is_ignored_by_patterns(rel_path, ignore_patterns):
                            try:
                                fsize = os.path.getsize(fpath)
                            except OSError:
                                fsize = 0
                            self._items.append(JunkItem(
                                category="ungitignored",
                                file_path=fpath,
                                size_bytes=fsize,
                                reason=f"{desc}。未被 `.gitignore` 忽略，"
                                       f"建议在 `.gitignore` 中添加忽略规则。",
                                safe_to_delete=False,
                            ))
                        break  # 一个文件只匹配一个模式

    def _is_ignored_by_patterns(self, rel_path: str, patterns: Set[str]) -> bool:
        """检查相对路径是否被 .gitignore 模式覆盖"""
        for pattern in patterns:
            # 简化匹配：模式在路径中
            if pattern.rstrip("/") in rel_path:
                return True
            # 通配符匹配
            if pattern.startswith("*.") and rel_path.endswith(pattern[1:]):
                return True
            if pattern.endswith("/") and rel_path.startswith(pattern):
                return True
            if pattern == rel_path:
                return True
        return False

    # ─── 检测 6: 孤立文件 ──────────────────────────────────────────

    def _detect_orphans(self, project_path: str):
        """检测超过 30 天未修改且不在任何 import 链中的孤立文件"""
        # 收集所有文件
        all_files: List[str] = []
        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if self._scope.should_scan(os.path.join(root, d))]
            if os.path.basename(root) == "__pycache__":
                continue
            for f in files:
                fpath = os.path.join(root, f)
                all_files.append(fpath)

        # 构建 import 关系图：哪些文件被 import 了
        imported_files: Set[str] = set()
        import_graph = self._build_import_graph(all_files)

        for imports in import_graph.values():
            for imp in imports:
                imported_files.add(imp)

        cutoff_time = datetime.now() - timedelta(days=30)

        for fpath in all_files:
            # 跳过非代码文件
            if not self._is_code_file(fpath):
                continue

            rel_path = os.path.relpath(fpath, project_path).replace("\\", "/")

            # 检查修改时间
            try:
                mtime = datetime.fromtimestamp(os.path.getmtime(fpath))
            except OSError:
                continue

            if mtime > cutoff_time:
                continue  # 最近 30 天修改过，不孤立

            # 检查是否被 import
            if rel_path in imported_files or fpath in imported_files:
                continue

            # 检查是否是入口文件（含 main/if __name__）
            if self._is_entry_point(fpath):
                continue

            try:
                fsize = os.path.getsize(fpath)
            except OSError:
                fsize = 0

            days_ago = (datetime.now() - mtime).days
            self._items.append(JunkItem(
                category="orphan",
                file_path=fpath,
                size_bytes=fsize,
                reason=f"已有 {days_ago} 天未修改，且没有被项目中的任何其他文件引用（import）。"
                       f"很可能是被遗忘的、不再需要的文件。",
                safe_to_delete=False,
            ))

    def _build_import_graph(self, all_files: List[str]) -> Dict[str, Set[str]]:
        """
        构建 import 关系图

        Returns:
            {file_path: set of imported relative paths}
        """
        graph: Dict[str, Set[str]] = defaultdict(set)

        # 构建文件路径到模块名的映射
        path_to_module: Dict[str, str] = {}
        for fpath in all_files:
            fname = os.path.basename(fpath)
            if fname.endswith(".py"):
                module_name = fname[:-3]
                path_to_module[fpath] = module_name

        # 包含文件对应目录的路径映射
        for fpath in all_files:
            fname = os.path.basename(fpath)
            if fname.endswith(".py"):
                module_name = fname[:-3]
                # 构建完整路径映射
                parent_dir = os.path.dirname(fpath)
                for other_fpath in all_files:
                    other_dir = os.path.dirname(other_fpath)
                    other_name = os.path.basename(other_fpath)
                    if other_name.endswith(".py"):
                        other_module = other_name[:-3]
                        if other_module == module_name and other_dir == parent_dir:
                            continue

        # 解析每个文件的 import 语句
        import_re = re.compile(
            r'^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+))',
            re.MULTILINE
        )

        for fpath in all_files:
            if not fpath.endswith(".py"):
                continue
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue

            file_dir = os.path.dirname(fpath)

            for m in import_re.finditer(content):
                module = m.group(1) or m.group(2)
                if not module:
                    continue
                root_module = module.split(".")[0]

                # 尝试匹配本地文件
                for other_fpath in all_files:
                    other_name = os.path.basename(other_fpath)
                    if not other_name.endswith(".py"):
                        continue
                    other_module = other_name[:-3]
                    other_dir = os.path.dirname(other_fpath)

                    # 同目录匹配
                    if other_module == root_module and other_dir == file_dir:
                        rel = os.path.relpath(other_fpath, os.path.dirname(fpath)).replace("\\", "/")
                        graph[fpath].add(rel)
                        graph[fpath].add(other_fpath)
                    # 子目录匹配
                    elif other_module == root_module and other_dir.startswith(
                            os.path.join(file_dir, root_module)):
                        rel = os.path.relpath(other_fpath, os.path.dirname(fpath)).replace("\\", "/")
                        graph[fpath].add(rel)
                        graph[fpath].add(other_fpath)

        return graph

    def _is_code_file(self, fpath: str) -> bool:
        """判断是否为代码文件"""
        code_exts = {".py", ".pyw", ".pyx", ".pyi", ".js", ".ts", ".jsx", ".tsx",
                     ".java", ".go", ".rs", ".c", ".cpp", ".h", ".hpp"}
        return any(fpath.endswith(ext) for ext in code_exts)

    def _is_entry_point(self, fpath: str) -> bool:
        """判断文件是否为入口文件（含 main 函数或 if __name__ == '__main__'）"""
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except Exception:
            return False
        return bool(re.search(r'if\s+__name__\s*==\s*["\']__main__["\']', content))

    # ─── 辅助方法 ─────────────────────────────────────────────────

    def _hash_first_lines(self, fpath: str, n_lines: int) -> str:
        """计算文件前 N 行的 MD5 哈希"""
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                lines = []
                for i, line in enumerate(fh):
                    if i >= n_lines:
                        break
                    lines.append(line)
                content = "".join(lines)
                return hashlib.md5(content.encode("utf-8")).hexdigest()
        except Exception:
            return ""

    def _content_similarity(self, fpath1: str, fpath2: str, max_lines: int) -> float:
        """计算两个文件前 N 行的内容相似度"""
        try:
            with open(fpath1, "r", encoding="utf-8", errors="ignore") as fh:
                lines1 = [next(fh) for _ in range(max_lines)]
        except Exception:
            lines1 = []
        try:
            with open(fpath2, "r", encoding="utf-8", errors="ignore") as fh:
                lines2 = [next(fh) for _ in range(max_lines)]
        except Exception:
            lines2 = []

        if not lines1 and not lines2:
            return 1.0
        if not lines1 or not lines2:
            return 0.0

        return difflib.SequenceMatcher(None, "".join(lines1), "".join(lines2)).ratio()

    # ─── 报告生成 ─────────────────────────────────────────────────

    def _generate_report(self, project_path: str) -> str:
        """生成 Markdown 格式的垃圾检测报告"""
        lines = []

        # 分类统计
        cat_counts: Dict[str, int] = defaultdict(int)
        cat_sizes: Dict[str, int] = defaultdict(int)
        safe_count = 0
        confirm_count = 0
        total_size = 0

        for item in self._items:
            cat_counts[item.category] += 1
            cat_sizes[item.category] += item.size_bytes
            total_size += item.size_bytes
            if item.safe_to_delete:
                safe_count += 1
            else:
                confirm_count += 1

        # 格式化大小
        def fmt_size(b: int) -> str:
            if b >= 1024 * 1024:
                return f"{b / (1024 * 1024):.1f} MB"
            elif b >= 1024:
                return f"{b / 1024:.1f} KB"
            else:
                return f"{b} B"

        # 头部
        lines.append("# 垃圾文件检测报告")
        lines.append("")
        lines.append(f"> 项目: `{project_path}`")
        lines.append(f"> 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # 总览
        lines.append("## 垃圾总览")
        lines.append("")
        lines.append(f"| 指标 | 数值 |")
        lines.append(f"|------|------|")
        lines.append(f"| 发现垃圾文件数 | **{len(self._items)}** |")
        lines.append(f"| 可释放空间 | **{fmt_size(total_size)}** |")
        lines.append(f"| 可安全删除 | {safe_count} 项 |")
        lines.append(f"| 需确认后删除 | {confirm_count} 项 |")
        lines.append("")

        if not self._items:
            lines.append("**恭喜，项目非常干净，没有发现垃圾文件！**")
            lines.append("")
            return "\n".join(lines)

        # 分类统计
        lines.append("### 按分类统计")
        lines.append("")
        lines.append("| 分类 | 数量 | 占用空间 | 说明 |")
        lines.append("|------|------|---------|------|")
        for cat in ["pycache", "duplicate", "zero_byte", "empty_shell", "ungitignored", "orphan"]:
            count = cat_counts.get(cat, 0)
            if count == 0:
                continue
            size = cat_sizes.get(cat, 0)
            label = CATEGORY_LABELS.get(cat, cat)
            safe_icon = "可安全删除" if cat in ("pycache", "zero_byte") else "需确认"
            lines.append(f"| {label} | {count} | {fmt_size(size)} | {safe_icon} |")
        lines.append("")

        lines.append("---")
        lines.append("")

        # 分类详细清单
        for cat in ["pycache", "duplicate", "zero_byte", "empty_shell", "ungitignored", "orphan"]:
            cat_items = [item for item in self._items if item.category == cat]
            if not cat_items:
                continue

            label = CATEGORY_LABELS.get(cat, cat)
            lines.append(f"## {label}（{len(cat_items)} 项）")
            lines.append("")

            # 通俗解释
            explanation = CATEGORY_EXPLANATIONS.get(cat, "")
            if explanation:
                lines.append(f"> {explanation}")
                lines.append("")

            # 排序：按大小降序
            cat_items.sort(key=lambda x: -x.size_bytes)

            for item in cat_items:
                safe_tag = "可安全删除" if item.safe_to_delete else "建议确认后删除"
                lines.append(f"### {safe_tag}")
                lines.append("")
                lines.append(f"- **文件**: `{item.file_path}`")
                if item.size_bytes > 0:
                    lines.append(f"- **大小**: {fmt_size(item.size_bytes)}")
                lines.append(f"- **原因**: {item.reason}")
                lines.append("")

        lines.append("---")
        lines.append("")

        # 清理建议
        lines.append("## 清理建议")
        lines.append("")

        safe_items = [item for item in self._items if item.safe_to_delete]
        confirm_items = [item for item in self._items if not item.safe_to_delete]

        if safe_items:
            safe_size = sum(item.size_bytes for item in safe_items)
            lines.append(f"### 第一步：安全清理（{len(safe_items)} 项，可释放 {fmt_size(safe_size)}）")
            lines.append("")
            lines.append("以下类型的文件可以放心删除，不会影响项目运行：")
            lines.append("")
            lines.append("- **Python 编译缓存（__pycache__ / .pyc）**：删除后 Python 会自动重新生成")
            lines.append("- **0 字节空文件**：不包含任何内容，删除无影响")
            lines.append("")
            lines.append("```bash")
            lines.append("# 清理 Python 编译缓存")
            lines.append("find . -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null")
            lines.append("find . -type f -name '*.pyc' -delete")
            lines.append("find . -type f -name '*.pyo' -delete")
            lines.append("")
            lines.append("# 清理 0 字节文件")
            lines.append("find . -type f -size 0 -not -name '__init__.py' -not -name '.gitkeep' -delete")
            lines.append("```")
            lines.append("")

        if confirm_items:
            confirm_size = sum(item.size_bytes for item in confirm_items)
            lines.append(f"### 第二步：确认后清理（{len(confirm_items)} 项，可释放 {fmt_size(confirm_size)}）")
            lines.append("")
            lines.append("以下类型的文件建议先确认再删除：")
            lines.append("")
            lines.append("- **重复文件**：确认保留哪一份副本，删除其余")
            lines.append("- **空壳文件**：确认是否真的没有使用计划")
            lines.append("- **应被忽略的文件**：更新 `.gitignore` 而非直接删除")
            lines.append("- **孤立文件**：确认是否真的不再需要")
            lines.append("")

        lines.append("### 清理注意事项")
        lines.append("")
        lines.append("1. **清理前先备份**：建议先提交 Git 或备份项目，以便恢复")
        lines.append("2. **分批清理**：按分类分批清理，每批清理后运行测试确保正常")
        lines.append("3. **更新 .gitignore**：清理后更新 `.gitignore` 文件，防止同类垃圾再次出现")
        lines.append("4. **Git 历史**：已删除的文件仍可通过 Git 历史找回，不用担心误删")
        lines.append("")

        lines.append("---")
        lines.append("")
        lines.append(f"*报告由 CodeRef-AI JunkDetector v1.0 生成*")

        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════
# 独立运行入口
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("用法: python junk_detector.py <项目路径>")
        print("示例: python junk_detector.py /path/to/project")
        sys.exit(1)

    target_path = sys.argv[1]
    if not os.path.isdir(target_path):
        print(f"错误: 路径不存在或不是目录: {target_path}")
        sys.exit(1)

    detector = JunkDetector()
    report = detector.detect(target_path)
    print(report)
