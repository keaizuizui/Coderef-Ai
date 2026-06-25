# -*- coding: utf-8 -*-
"""
完整性检查器 —— 检测 AI 生成代码的遗漏、不一致和残留问题

场景：AI 有幻觉，该删的没删，文档不完整。需要检查项目代码/文档的完整性。

检测维度：
1. TODO/FIXME/HACK/XXX/BUG 注释：未完成的工作标记，按优先级排序
2. 文档覆盖率：每个业务模块目录是否都有对应文档；文档中提到的文件是否真实存在
3. 孤立引用：Git 仓库中已删除但代码中仍有引用的文件
4. 文件格式问题：文件末尾缺少换行符
5. 孤立测试文件：test_*.py 存在但对应的源文件不存在

与 CodeSimplifier / GovernanceAuditor / BlindSpotDetector 互补：
- CodeSimplifier 聚焦代码精简（YAGNI、死代码、过度工程）
- GovernanceAuditor 聚焦安全与架构合规（铁律、错题本）
- BlindSpotDetector 聚焦知识盲区（三方盲区）
- IntegrityChecker 聚焦完整性（遗漏、不一致、残留）

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

# 创建共享过滤器实例
_sf = SharedFilter()


# ═══════════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════════

@dataclass
class IntegrityIssue:
    """单条完整性问题

    Attributes:
        category: 分类（todo_fixme / doc_coverage / dead_link /
                  orphan_test / missing_newline）
        severity: 严重程度（critical / high / medium / low）
        file_path: 文件路径
        line: 行号（0 表示不适用）
        content: 相关内容
        suggestion: 修复建议
    """
    category: str
    severity: str
    file_path: str
    line: int
    content: str
    suggestion: str


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}

CATEGORY_LABELS = {
    "todo_fixme": "未完成标记",
    "doc_coverage": "文档覆盖率",
    "dead_link": "文档死链接",
    "orphan_test": "孤立测试文件",
    "missing_newline": "缺少换行符",
}

# TODO/FIXME 优先级排序：FIXME/BUG > HACK > TODO > XXX
TAG_PRIORITY = {
    "FIXME": 0, "BUG": 0, "HACK": 1, "TODO": 2, "XXX": 3,
}
TAG_SEVERITY = {
    "FIXME": "high", "BUG": "critical", "HACK": "medium", "TODO": "low", "XXX": "low",
}


# ═══════════════════════════════════════════════════════════════════
# 完整性检查器
# ═══════════════════════════════════════════════════════════════════

class IntegrityChecker:
    """
    完整性检查器

    检测 AI 生成代码的遗漏、不一致和残留，确保项目代码和文档的完整性。
    """

    def __init__(self):
        self._all_py_files: List[str] = []
        self._all_imports: Dict[str, Set[str]] = {}  # file_path -> set of imports
        self._all_module_names: Set[str] = set()

    def check(self, project_path: str) -> str:
        """
        执行完整性检查并生成报告

        Args:
            project_path: 项目路径

        Returns:
            Markdown 格式的完整性检查报告
        """
        logger.info(f"[IntegrityChecker] 开始检查: {project_path}")

        # 加载项目专属的 cache 硬编码优化（白名单）
        SharedFilter.load_cache(project_path)

        # 收集项目基础信息
        self._collect_project_info(project_path)

        issues: List[IntegrityIssue] = []

        # 1. TODO/FIXME/HACK/XXX/BUG 注释
        issues.extend(self._check_todo_fixme(project_path))
        # 2. 文档覆盖率
        issues.extend(self._check_doc_coverage(project_path))
        # 3. 文档中的死链接
        issues.extend(self._check_dead_links(project_path))
        # 4. 孤立测试文件
        issues.extend(self._check_orphan_tests(project_path))
        # 5. 文件末尾缺少换行符
        issues.extend(self._check_missing_newlines(project_path))

        # 按严重程度排序
        issues.sort(key=lambda i: (SEVERITY_ORDER.get(i.severity, 9), i.file_path, i.line))

        logger.info(f"[IntegrityChecker] 检查完成: {len(issues)} 个问题")

        return self._generate_report(project_path, issues)

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
                    imports = self._extract_imports(fp)
                    self._all_imports[fp] = imports

        logger.info(f"[IntegrityChecker] 收集到 {len(self._all_py_files)} 个 .py 文件")

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
            m = re.match(r'from\s+([\w.]+)\s+import', stripped)
            if m:
                imports.add(m.group(1))
            m = re.match(r'import\s+([\w.]+)', stripped)
            if m:
                imports.add(m.group(1))
        return imports

    # ─── 检测规则 ─────────────────────────────────────────────────

    def _check_todo_fixme(self, project_path: str) -> List[IntegrityIssue]:
        """检测 TODO/FIXME/HACK/XXX/BUG 注释，按优先级排序"""
        issues = []
        tag_pattern = re.compile(r'\b(TODO|FIXME|HACK|XXX|BUG)\b', re.IGNORECASE)

        for fp in self._all_py_files:
            try:
                with open(fp, "r", encoding="utf-8") as f:
                    lines = f.readlines()
            except Exception:
                continue

            # 获取文档字符串行号，跳过文档字符串
            docstring_lines = _sf.get_docstring_lines([l.rstrip('\n') for l in lines])

            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                if not (stripped.startswith("#") or stripped.startswith("//")):
                    continue

                # 跳过文档字符串行
                if i in docstring_lines:
                    continue

                m = tag_pattern.search(stripped)
                if not m:
                    continue

                tag = m.group(1).upper()

                # 跳过检测器自身规则描述注释（如 "# TODO/FIXME 优先级排序"）
                if _sf.is_comment_about_self(stripped):
                    continue

                # 跳过小写 xxx 占位符（如 "# 如 cfg.xxx"）
                if tag == "XXX" and _sf.is_placeholder_xxx(stripped):
                    continue

                severity = TAG_SEVERITY.get(tag, "low")
                # 提取标签后的内容
                after_tag = stripped[m.end():].strip().lstrip(":- ")

                issues.append(IntegrityIssue(
                    category="todo_fixme",
                    severity=severity,
                    file_path=fp,
                    line=i,
                    content=f"[{tag}] {after_tag}" if after_tag else f"[{tag}]",
                    suggestion=f"处理此 {tag} 标记，或如果不再需要则删除注释",
                ))

        # 按标签优先级 + 严重程度排序
        issues.sort(key=lambda i: (
            SEVERITY_ORDER.get(i.severity, 9),
            TAG_PRIORITY.get(i.content.split("]")[0].lstrip("["), 9),
            i.file_path, i.line,
        ))

        logger.info(f"[IntegrityChecker] TODO/FIXME: {len(issues)} 个")
        return issues

    def _check_doc_coverage(self, project_path: str) -> List[IntegrityIssue]:
        """检查文档覆盖率：每个业务模块目录是否都有对应文档"""
        issues = []

        docs_dir = os.path.join(project_path, "docs")
        if not os.path.isdir(docs_dir):
            issues.append(IntegrityIssue(
                category="doc_coverage",
                severity="high",
                file_path=project_path,
                line=0,
                content="项目没有 docs/ 目录",
                suggestion="创建 docs/ 目录并为核心模块补充文档",
            ))
            return issues

        # 收集 docs/ 下所有 .md 文件
        doc_files: Set[str] = set()
        for root, _, files in os.walk(docs_dir):
            for f in files:
                if f.endswith(".md"):
                    doc_files.add(os.path.splitext(f)[0].lower())

        # 按目录分组 .py 文件
        dir_py_count: Dict[str, int] = defaultdict(int)
        dir_py_files: Dict[str, List[str]] = defaultdict(list)
        for fp in self._all_py_files:
            d = os.path.dirname(fp)
            dir_py_count[d] += 1
            dir_py_files[d].append(os.path.basename(fp))

        # 只检查代码目录（排除 docs/、测试目录等）
        code_dirs = {d for d in dir_py_count if not d.startswith(docs_dir)}

        for py_dir in sorted(code_dirs):
            py_count = dir_py_count[py_dir]
            if py_count == 0:
                continue
            rel = os.path.relpath(py_dir, project_path)
            dir_name = os.path.basename(py_dir).lower()

            has_doc = any(dir_name in dn or dn in dir_name for dn in doc_files)
            if not has_doc and py_count >= 2:
                # 只报告有 >=2 个 .py 文件的目录
                issues.append(IntegrityIssue(
                    category="doc_coverage",
                    severity="medium",
                    file_path=py_dir,
                    line=0,
                    content=f"目录 '{rel}' 有 {py_count} 个 Python 文件，但 docs/ 中无对应文档",
                    suggestion=f"为 '{rel}' 目录创建文档，说明模块功能和用法",
                ))

        logger.info(f"[IntegrityChecker] 文档覆盖率问题: {len(issues)} 个")
        return issues

    def _check_dead_links(self, project_path: str) -> List[IntegrityIssue]:
        """检查文档中的死链接：文档中引用了不存在的文件"""
        issues = []

        docs_dir = os.path.join(project_path, "docs")
        if not os.path.isdir(docs_dir):
            return issues

        # 收集所有真实存在的文件路径（相对于项目根目录）
        all_real_files: Set[str] = set()
        for root, _, files in os.walk(project_path):
            for f in files:
                rel = os.path.relpath(os.path.join(root, f), project_path)
                all_real_files.add(rel.replace("\\", "/"))
                all_real_files.add(f)  # 也加入纯文件名

        # 文件引用模式：`file.py`、[file](path)、相对路径
        file_ref_pattern = re.compile(r'`([\w./-]+\.(?:py|md|json|yaml|yml|toml|cfg|ini|txt))`')
        link_pattern = re.compile(r'\[([^\]]*)\]\(([^)]+)\)')

        for root, _, files in os.walk(docs_dir):
            for f in files:
                if not f.endswith(".md"):
                    continue
                fp = os.path.join(root, f)
                try:
                    with open(fp, "r", encoding="utf-8") as fh:
                        content = fh.read()
                except Exception:
                    continue

                # 检查反引号中的文件引用
                for m in file_ref_pattern.finditer(content):
                    ref = m.group(1)
                    if ref not in all_real_files:
                        # 检查是否是相对路径
                        doc_dir = os.path.dirname(fp)
                        candidate = os.path.normpath(os.path.join(doc_dir, ref))
                        cand_rel = os.path.relpath(candidate, project_path).replace("\\", "/")
                        if cand_rel not in all_real_files:
                            issues.append(IntegrityIssue(
                                category="dead_link",
                                severity="medium",
                                file_path=fp,
                                line=0,
                                content=f"文档引用了不存在的文件: `{ref}`",
                                suggestion=f"检查文件 '{ref}' 是否已被删除或重命名，更新文档中的引用",
                            ))

                # 检查 Markdown 链接
                for m in link_pattern.finditer(content):
                    url = m.group(2)
                    if url.startswith(("http://", "https://", "#", "mailto:")):
                        continue
                    # 本地文件链接
                    link_target = os.path.normpath(
                        os.path.join(os.path.dirname(fp), url)
                    )
                    if not os.path.exists(link_target):
                        issues.append(IntegrityIssue(
                            category="dead_link",
                            severity="medium",
                            file_path=fp,
                            line=0,
                            content=f"文档链接指向不存在的文件: [{m.group(1)}]({url})",
                            suggestion=f"检查链接目标 '{url}' 是否有效，更新或删除死链接",
                        ))

        logger.info(f"[IntegrityChecker] 文档死链接: {len(issues)} 个")
        return issues

    def _check_orphan_tests(self, project_path: str) -> List[IntegrityIssue]:
        """检测孤立测试文件：test_*.py 对应的源文件不存在"""
        issues = []

        test_files = [fp for fp in self._all_py_files
                      if os.path.basename(fp).startswith("test_")]

        for tf in test_files:
            test_name = os.path.basename(tf)
            # test_foo.py → foo.py
            source_name = test_name[5:]  # 去掉 "test_" 前缀

            # 在同目录和上级目录查找对应的源文件
            test_dir = os.path.dirname(tf)
            found = False

            for search_dir in [test_dir, os.path.dirname(test_dir)]:
                candidate = os.path.join(search_dir, source_name)
                if os.path.exists(candidate):
                    found = True
                    break
                # 也检查去掉 test_ 前缀后的模块名
                for fp in self._all_py_files:
                    if os.path.basename(fp) == source_name:
                        found = True
                        break
                if found:
                    break

            if not found:
                issues.append(IntegrityIssue(
                    category="orphan_test",
                    severity="low",
                    file_path=tf,
                    line=0,
                    content=f"测试文件 '{test_name}' 对应的源文件 '{source_name}' 不存在",
                    suggestion=f"确认源文件 '{source_name}' 是否已被删除，如果已删除则此测试文件也应一并删除",
                ))

        logger.info(f"[IntegrityChecker] 孤立测试文件: {len(issues)} 个")
        return issues

    def _check_missing_newlines(self, project_path: str) -> List[IntegrityIssue]:
        """检测文件末尾是否缺少换行符"""
        issues = []

        for fp in self._all_py_files:
            try:
                with open(fp, "rb") as f:
                    # 读取文件末尾几个字节
                    f.seek(-1, os.SEEK_END)
                    last_byte = f.read(1)
            except Exception:
                continue

            if last_byte != b"\n":
                issues.append(IntegrityIssue(
                    category="missing_newline",
                    severity="low",
                    file_path=fp,
                    line=0,
                    content="文件末尾缺少换行符",
                    suggestion="在文件末尾添加一个空行，符合 POSIX 标准和大多数编辑器的约定",
                ))

        logger.info(f"[IntegrityChecker] 缺少换行符: {len(issues)} 个")
        return issues

    # ─── 报告生成 ─────────────────────────────────────────────────

    def _generate_report(self, project_path: str, issues: List[IntegrityIssue]) -> str:
        """生成 Markdown 格式的完整性检查报告"""
        # 分类统计
        cat_counts: Dict[str, int] = defaultdict(int)
        sev_counts: Dict[str, int] = defaultdict(int)
        for i in issues:
            cat_counts[i.category] += 1
            sev_counts[i.severity] += 1

        lines = []
        lines.append("# 完整性检查报告")
        lines.append("")
        lines.append(f"> 项目路径: `{project_path}`")
        lines.append(f"> 扫描文件数: {len(self._all_py_files)}")
        lines.append(f"> 发现问题: {len(issues)} 个")
        lines.append("")
        lines.append("> 完整性 = 该有的都有 + 该删的都删了 + 文档和代码一致。")
        lines.append("> 本报告检查 AI 生成代码的遗漏、不一致和残留问题。")
        lines.append("")
        lines.append("---")
        lines.append("")

        # 完整性总览
        lines.append("## 完整性总览")
        lines.append("")
        lines.append("### 按分类统计")
        lines.append("")
        lines.append("| 分类 | 数量 | 说明 |")
        lines.append("|------|------|------|")
        for cat, label in CATEGORY_LABELS.items():
            count = cat_counts.get(cat, 0)
            if count > 0:
                desc = {
                    "todo_fixme": "代码中的未完成标记",
                    "doc_coverage": "缺少文档的模块",
                    "dead_link": "文档中引用了不存在的文件",
                    "orphan_test": "测试文件对应的源文件不存在",
                    "missing_newline": "文件末尾缺少换行符",
                }.get(cat, "")
                lines.append(f"| {label} | {count} | {desc} |")
        lines.append("")

        lines.append("### 按严重程度统计")
        lines.append("")
        lines.append("| 严重程度 | 数量 |")
        lines.append("|---------|------|")
        for sev in ["critical", "high", "medium", "low"]:
            count = sev_counts.get(sev, 0)
            if count > 0:
                label = {"critical": "严重", "high": "高", "medium": "中", "low": "低"}[sev]
                lines.append(f"| {label} | {count} |")
        lines.append("")

        if not issues:
            lines.append("本次检查未发现问题，项目完整性良好。")
            return "\n".join(lines)

        lines.append("---")
        lines.append("")

        # 按分类展示详情
        for cat, label in CATEGORY_LABELS.items():
            cat_issues = [i for i in issues if i.category == cat]
            if not cat_issues:
                continue

            lines.append(f"## {label}（{len(cat_issues)} 个）")
            lines.append("")

            if cat == "todo_fixme":
                lines.append("> 优先级排序: FIXME/BUG > HACK > TODO > XXX")
                lines.append("")

            # 每类最多展示 50 条
            display = cat_issues[:50]
            for i in display:
                sev_icon = {"critical": "!!", "high": "!", "medium": "~", "low": "-"}[i.severity]
                lines.append(f"### [{sev_icon}] {os.path.basename(i.file_path)}")
                if i.line > 0:
                    lines.append(f"L{i.line}: `{i.content}`")
                else:
                    lines.append(f"`{i.content}`")
                lines.append("")
                lines.append(f"- **文件**: `{i.file_path}`")
                lines.append(f"- **建议**: {i.suggestion}")
                lines.append("")

            if len(cat_issues) > 50:
                lines.append(f"*... 还有 {len(cat_issues) - 50} 条未展示*")
                lines.append("")

        lines.append("---")
        lines.append("")

        # 建议
        lines.append("## 修复建议")
        lines.append("")
        lines.append("1. **FIXME/BUG**：立即处理，这些是已知的缺陷")
        lines.append("2. **HACK**：评估是否需要重构为正式实现")
        lines.append("3. **TODO**：排入迭代计划，超过 30 天的 TODO 考虑删除")
        lines.append("4. **文档覆盖率**：为核心模块补充 README")
        lines.append("5. **死链接**：更新文档中过时的文件引用")
        lines.append("6. **孤立测试**：删除无对应源文件的测试")
        lines.append("7. **换行符**：在文件末尾添加空行（编辑器通常自动处理）")
        lines.append("")
        lines.append("---")
        lines.append("*报告由 CodeRef-AI IntegrityChecker v1.0 生成*")

        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════════
# 独立运行入口
# ═══════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys

    target = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    checker = IntegrityChecker()
    report = checker.check(target)
    print(report)
