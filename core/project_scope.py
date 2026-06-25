# -*- coding: utf-8 -*-
"""
通用项目边界检测器 —— 自动判断哪些目录属于"项目代码"，哪些是"外部/依赖/标准库"

核心问题：CodeRef 是通用工具，不能硬编码 Python3.14、venv 等目录名。
本模块通过目录特征自动判断，而不是硬编码目录名。

检测规则（按优先级）：
1. 项目根标志：包含 setup.py、pyproject.toml 等项目配置文件
2. 已知非项目特征：__pycache__、.git、node_modules 等通用约定目录
3. 虚拟环境检测：pyvenv.cfg 或 bin/activate + lib/ 结构
4. 标准库/运行时检测：包含 os.py、sys.py 等标志性文件
5. 包管理器缓存检测：路径包含 site-packages
6. 数据/资源目录检测：只包含非代码文件

作者: PersuadeAI Team
版本: v1.0
"""

import os
import re
from typing import Dict, List, Set, Optional
from collections import deque, defaultdict
from dataclasses import dataclass, field

from loguru import logger


# ═══════════════════════════════════════════════════════════════════
# 常量定义
# ═══════════════════════════════════════════════════════════════════

# 项目根标志文件/目录
PROJECT_ROOT_MARKERS = {
    "setup.py", "setup.cfg", "pyproject.toml", "package.json",
    "Cargo.toml", "go.mod", "pom.xml", "build.gradle",
    "Makefile", "CMakeLists.txt", ".git",
}

# 已知非项目目录名（通用约定，所有语言适用）
KNOWN_NON_PROJECT_DIRS = {
    "__pycache__", ".git", "node_modules", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".tox", "dist", "build",
}

# *.egg-info 匹配模式
EGG_INFO_PATTERN = re.compile(r'^.+\.egg-info$')

# 标准库标志性文件（出现 3 个以上即判定为标准库/运行时）
STDLIB_INDICATOR_FILES = {
    "os.py", "sys.py", "__future__.py", "abc.py", "collections.py",
    "io.py", "re.py", "json.py", "functools.py", "itertools.py",
    "pathlib.py", "typing.py", "dataclasses.py", "inspect.py",
    "importlib.py", "logging.py", "argparse.py", "threading.py",
    "multiprocessing.py", "subprocess.py", "socket.py", "ssl.py",
    "hashlib.py", "datetime.py", "time.py", "math.py", "random.py",
    "struct.py", "textwrap.py", "difflib.py", "traceback.py",
    "contextlib.py", "copy.py", "copyreg.py", "operator.py",
    "enum.py", "numbers.py", "collections/__init__.py",
    "importlib/__init__.py", "encodings/__init__.py",
}

# 代码文件扩展名
# 源代码文件扩展名（不含编译产物）
SOURCE_EXTENSIONS = {
    ".py", ".pyw", ".pyx", ".pyi",
    ".js", ".ts", ".jsx", ".tsx",
    ".go", ".rs", ".java", ".c", ".cpp", ".h", ".hpp", ".cs",
    ".rb", ".php", ".swift", ".kt", ".scala",
}

# 代码文件扩展名（含编译产物，用于"有代码文件"判断）
CODE_EXTENSIONS = SOURCE_EXTENSIONS | {
    ".pyd", ".pyo", ".so", ".dll", ".dylib",
}

# 数据/资源文件扩展名
DATA_EXTENSIONS = {
    ".json", ".csv", ".txt", ".md", ".yaml", ".yml", ".toml",
    ".xml", ".ini", ".cfg", ".conf", ".properties",
}


# ═══════════════════════════════════════════════════════════════════
# 项目边界检测器
# ═══════════════════════════════════════════════════════════════════

class ProjectScope:
    """
    通用项目边界检测器

    通过目录特征自动判断哪些目录属于"项目代码"，
    哪些是"外部/依赖/标准库/缓存"。

    用法:
        scope = ProjectScope("/path/to/project")
        scope.analyze()
        if scope.should_scan("/path/to/project/src"):
            # 扫描该目录
            pass
    """

    def __init__(self, project_path: str):
        """
        Args:
            project_path: 项目根目录路径（绝对路径）
        """
        self.project_path = os.path.abspath(project_path)
        self._project_dirs: Set[str] = set()       # 属于项目的目录（绝对路径）
        self._skip_dirs: Set[str] = set()          # 应跳过的目录（绝对路径）
        self._skip_reasons: Dict[str, str] = {}     # 跳过原因：dir_path -> reason
        self._analyzed = False

    def analyze(self) -> None:
        """分析项目结构，建立边界"""
        if self._analyzed:
            return

        if not os.path.isdir(self.project_path):
            logger.warning(f"[ProjectScope] 项目路径不存在: {self.project_path}")
            self._analyzed = True
            return

        # 项目根自身属于项目
        self._project_dirs.add(self.project_path)

        # BFS 遍历子目录
        queue = deque()
        # 初始化：项目根的直接子目录
        try:
            entries = os.listdir(self.project_path)
        except PermissionError:
            logger.warning(f"[ProjectScope] 无权限访问: {self.project_path}")
            self._analyzed = True
            return

        for entry in entries:
            full_path = os.path.join(self.project_path, entry)
            if os.path.isdir(full_path):
                queue.append(full_path)

        while queue:
            dir_path = queue.popleft()
            dir_name = os.path.basename(dir_path)

            # 按规则判断
            skip_reason = self._classify_dir(dir_path, dir_name)

            if skip_reason:
                self._skip_dirs.add(dir_path)
                self._skip_reasons[dir_path] = skip_reason
                # 一旦判定为"跳过"，其子目录也全部跳过（不递归）
            else:
                self._project_dirs.add(dir_path)
                # 继续探索子目录
                try:
                    sub_entries = os.listdir(dir_path)
                except PermissionError:
                    continue
                for entry in sub_entries:
                    full_path = os.path.join(dir_path, entry)
                    if os.path.isdir(full_path):
                        queue.append(full_path)

        self._analyzed = True
        
        # 后处理1：回溯标记"空壳父目录"
        # 如果一个目录被标记为项目目录，但它下面没有任何项目子目录，
        # 且自身不直接包含代码文件，则回溯标记为跳过
        self._backtrack_empty_parents()
        
        # 后处理2：运行时污染清理
        # 如果一个目录的兄弟目录中有被标记为"标准库/运行时"的，
        # 则该目录及其所有子目录也应跳过（它们是运行时的一部分）
        self._backtrack_runtime_siblings()
        
        logger.info(
            f"[ProjectScope] 分析完成: "
            f"项目目录 {len(self._project_dirs)} 个, "
            f"跳过目录 {len(self._skip_dirs)} 个"
        )

    def _classify_dir(self, dir_path: str, dir_name: str) -> Optional[str]:
        """
        按规则分类目录，返回跳过原因（None 表示属于项目）

        Args:
            dir_path: 目录绝对路径
            dir_name: 目录名

        Returns:
            跳过原因字符串，None 表示属于项目
        """
        # 规则 1: 项目根标志（子目录包含项目配置文件 → 可能是子项目，仍属于项目）
        # 注意：这里不跳过，只是标记

        # 规则 2: 已知非项目特征
        if dir_name in KNOWN_NON_PROJECT_DIRS:
            return f"已知非项目目录: {dir_name}"
        if EGG_INFO_PATTERN.match(dir_name):
            return f"Python 打包信息: {dir_name}"

        # 规则 3: 虚拟环境检测
        if self._is_virtual_env(dir_path):
            return "虚拟环境"

        # 规则 4: 标准库/运行时检测
        if self._is_stdlib(dir_path):
            return "标准库/运行时"

        # 规则 5: 包管理器缓存检测
        if "site-packages" in dir_path.replace("\\", "/").split("/"):
            return "第三方包缓存 (site-packages)"

        # 规则 6: 数据/资源目录检测
        if self._is_data_only_dir(dir_path):
            return "数据/资源目录（无非代码文件）"

        return None

    def _backtrack_empty_parents(self):
        """回溯标记空壳父目录：子目录全被跳过 + 自身无代码文件 → 也跳过"""
        changed = True
        while changed:
            changed = False
            to_remove = []
            for dir_path in self._project_dirs:
                # 检查子目录是否全部被跳过
                try:
                    sub_entries = os.listdir(dir_path)
                except (PermissionError, OSError):
                    continue
                
                has_project_subdir = False
                has_code_file = False
                for entry in sub_entries:
                    full = os.path.join(dir_path, entry)
                    if os.path.isdir(full) and full in self._project_dirs:
                        has_project_subdir = True
                        break
                    if os.path.isfile(full):
                        ext = os.path.splitext(entry)[1].lower()
                        if ext in SOURCE_EXTENSIONS:  # 只看源代码，不看编译产物
                            has_code_file = True
                
                if not has_project_subdir and not has_code_file:
                    self._skip_dirs.add(dir_path)
                    self._skip_reasons[dir_path] = "空壳父目录（子目录全被跳过，自身无代码文件）"
                    to_remove.append(dir_path)
                    changed = True
            
            for d in to_remove:
                self._project_dirs.discard(d)

    def _backtrack_runtime_siblings(self):
        """运行时污染清理：如果兄弟目录中有标准库，则同层所有目录也跳过"""
        # 收集所有"标准库/运行时"标记的目录
        runtime_dirs = set()
        for d, reason in self._skip_reasons.items():
            if "标准库" in reason:
                runtime_dirs.add(d)
        
        if not runtime_dirs:
            return
        
        # 对每个标准库目录，找到其父目录，将父目录下的所有兄弟目录也标记为跳过
        siblings_to_skip = set()
        for rt_dir in runtime_dirs:
            parent = os.path.dirname(rt_dir)
            if parent == self.project_path:
                continue  # 不影响项目根的子目录（除非项目根本身就是运行时）
            try:
                entries = os.listdir(parent)
            except (PermissionError, OSError):
                continue
            for entry in entries:
                full = os.path.join(parent, entry)
                if os.path.isdir(full) and full in self._project_dirs:
                    siblings_to_skip.add(full)
        
        # 递归：被标记的兄弟目录的子目录也全部跳过
        for d in siblings_to_skip:
            self._skip_dirs.add(d)
            self._skip_reasons[d] = "运行时子目录（兄弟目录为标准库/运行时）"
            self._project_dirs.discard(d)
            # 递归标记子目录
            try:
                for entry in os.listdir(d):
                    full = os.path.join(d, entry)
                    if os.path.isdir(full) and full in self._project_dirs:
                        self._skip_dirs.add(full)
                        self._skip_reasons[full] = "运行时子目录（父目录为运行时的一部分）"
                        self._project_dirs.discard(full)
            except (PermissionError, OSError):
                pass
        
        # 回溯父目录：如果父目录现在没有项目子目录了
        if siblings_to_skip:
            self._backtrack_empty_parents()

    def _is_virtual_env(self, dir_path: str) -> bool:
        """检测是否为虚拟环境"""
        # 方法 1: 包含 pyvenv.cfg
        if os.path.isfile(os.path.join(dir_path, "pyvenv.cfg")):
            return True
        # 方法 2: 同时包含 bin/activate 和 lib/ 目录结构
        has_activate = (
            os.path.isfile(os.path.join(dir_path, "bin", "activate")) or
            os.path.isfile(os.path.join(dir_path, "Scripts", "activate.bat")) or
            os.path.isfile(os.path.join(dir_path, "Scripts", "activate"))
        )
        has_lib = os.path.isdir(os.path.join(dir_path, "lib"))
        if has_activate and has_lib:
            return True
        return False

    def _is_stdlib(self, dir_path: str) -> bool:
        """检测是否为标准库/运行时目录"""
        try:
            entries = set(os.listdir(dir_path))
        except PermissionError:
            return False

        # 统计标准库标志性文件数量
        indicator_count = 0
        for indicator in STDLIB_INDICATOR_FILES:
            if indicator in entries:
                indicator_count += 1

        return indicator_count >= 3

    def _is_data_only_dir(self, dir_path: str) -> bool:
        """检测是否为数据/资源目录（只包含非代码文件）"""
        try:
            entries = os.listdir(dir_path)
        except PermissionError:
            return False

        if not entries:
            return False

        has_code_file = False
        has_data_file = False

        for entry in entries:
            full_path = os.path.join(dir_path, entry)
            if os.path.isdir(full_path):
                # 包含子目录 → 不是纯数据目录
                return False
            ext = os.path.splitext(entry)[1].lower()
            if ext in CODE_EXTENSIONS:
                has_code_file = True
            if ext in DATA_EXTENSIONS or ext in ("",):
                has_data_file = True

        # 只有非代码文件且没有代码文件
        return has_data_file and not has_code_file

    def should_scan(self, dir_path: str) -> bool:
        """
        判断目录是否应该被扫描

        Args:
            dir_path: 目录路径（可以是相对路径或绝对路径）

        Returns:
            True 表示应该扫描，False 表示应该跳过
        """
        if not self._analyzed:
            self.analyze()

        abs_path = os.path.abspath(dir_path)

        # 如果在跳过集合中 → 不扫描
        if abs_path in self._skip_dirs:
            return False

        # 如果在项目集合中 → 扫描
        if abs_path in self._project_dirs:
            return True

        # 未知目录：默认扫描（保守策略）
        return True

    def get_project_dirs(self) -> Set[str]:
        """获取所有属于项目的目录"""
        if not self._analyzed:
            self.analyze()
        return self._project_dirs.copy()

    def get_skip_dirs(self) -> Set[str]:
        """获取所有应跳过的目录"""
        if not self._analyzed:
            self.analyze()
        return self._skip_dirs.copy()

    def get_stats(self) -> Dict:
        """
        返回统计信息

        Returns:
            {
                "project_dir_count": int,
                "skip_dir_count": int,
                "skip_reasons": {reason: count},
            }
        """
        if not self._analyzed:
            self.analyze()

        reason_counts: Dict[str, int] = defaultdict(int)
        for reason in self._skip_reasons.values():
            reason_counts[reason] += 1

        return {
            "project_dir_count": len(self._project_dirs),
            "skip_dir_count": len(self._skip_dirs),
            "skip_reasons": dict(reason_counts),
        }


# ═══════════════════════════════════════════════════════════════════
# 独立运行测试
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    import json

    target = os.path.abspath(".")
    if len(sys.argv) > 1:
        target = sys.argv[1]

    print(f"ProjectScope 测试运行")
    print(f"扫描路径: {target}")
    print(f"{'=' * 60}")

    scope = ProjectScope(target)
    scope.analyze()

    stats = scope.get_stats()
    print(f"\n## 统计信息")
    print(f"项目目录数: {stats['project_dir_count']}")
    print(f"跳过目录数: {stats['skip_dir_count']}")
    print(f"\n## 跳过原因分布")
    for reason, count in sorted(stats['skip_reasons'].items(), key=lambda x: -x[1]):
        print(f"  {reason}: {count}")

    print(f"\n## 项目目录（前 20 个）")
    for d in sorted(scope.get_project_dirs())[:20]:
        rel = os.path.relpath(d, target)
        print(f"  [SCAN] {rel}")

    print(f"\n## 跳过目录（前 20 个）")
    for d in sorted(scope.get_skip_dirs())[:20]:
        rel = os.path.relpath(d, target)
        reason = scope._skip_reasons.get(d, "未知")
        print(f"  [SKIP] {rel} ({reason})")
