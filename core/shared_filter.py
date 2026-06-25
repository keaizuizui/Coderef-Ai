# -*- coding: utf-8 -*-
"""
共享过滤工具 —— 检测器的通用误报过滤器

所有检测器共享的通用过滤逻辑，避免检测器自身的规则定义字符串被误报。

设计原则：
1. 通用性：不依赖特定检测器的上下文
2. 可组合：每个过滤方法独立，可选择性使用
3. 零依赖：只依赖 Python 标准库

用法示例:
    from core.shared_filter import SharedFilter

    sf = SharedFilter()
    # 获取文档字符串行号
    doc_lines = sf.get_docstring_lines(file_lines)
    # 判断是否是规则定义行
    if sf.is_pattern_def_line(line):
        continue
    # 判断是否在 try 块中
    if sf.is_in_try_block(file_lines, line_idx):
        continue
"""

import re
from typing import List, Set


class SharedFilter:
    """检测器通用误报过滤器"""

    # ─── 文档字符串解析 ────────────────────────────────────────────

    @staticmethod
    def get_docstring_lines(lines: List[str]) -> Set[int]:
        """
        解析文档字符串所在的行号集合

        返回所有在文档字符串内的行号（1-based）。

        Args:
            lines: 文件内容按行分割的列表

        Returns:
            文档字符串行号集合
        """
        doc_lines = set()
        in_docstring = False
        docstring_quote = None

        for i, line in enumerate(lines, 1):
            stripped = line.strip()
            if not in_docstring:
                if stripped.startswith('"""') or stripped.startswith("'''"):
                    in_docstring = True
                    docstring_quote = stripped[:3]
                    doc_lines.add(i)
                    # 单行文档字符串
                    if len(stripped) > 3 and stripped.endswith(docstring_quote):
                        in_docstring = False
            else:
                doc_lines.add(i)
                if stripped.endswith(docstring_quote):
                    in_docstring = False

        return doc_lines

    # ─── 规则定义行检测 ────────────────────────────────────────────

    # 安全/合规相关关键词（检测器规则定义中常出现的模式）
    _SECURITY_KEYWORDS = (
        r'password|passwd|secret|token|api_key|eval|exec|json\.loads|'
        r'pickle\.load|yaml\.load|marshal\.load|\.\.\/|\.\.\\\\|'
        r'MD5|SHA1|RC4|DES|innerHTML|dangerouslySetInnerHTML|'
        r'verify|ssl_verify|verify_ssl|md5|sha1|hashlib\.md5|hashlib\.sha1|'
        r'CWE-|OWASP|A0\d:\d{4}|SSRF|XSS|CSRF'
    )

    # 通用标签关键词（检测器规则定义中常出现的模式）
    _TAG_KEYWORDS = (
        r'TODO|FIXME|HACK|XXX|BUG|todo|fixme|hack|xxx|bug'
    )

    @staticmethod
    def is_pattern_def_line(line: str, keywords: str = None) -> bool:
        """
        判断行是否是检测器自身的规则定义（字符串字面量中的代码模式）

        检测两种模式：
        1. 正则模式字符串: r'...' 或 r"..."
        2. 普通字符串字面量中的代码模式: "...eval()..." 或 '...TODO...'

        Args:
            line: 待检查的行
            keywords: 额外的关键词正则（可选），追加到默认关键词列表

        Returns:
            True 表示这是规则定义行，应跳过
        """
        kw = keywords or ""
        if kw:
            combined = f"(?:{SharedFilter._SECURITY_KEYWORDS}|{kw})"
        else:
            combined = SharedFilter._SECURITY_KEYWORDS

        stripped = line.strip()

        # 正则模式字符串: r'...' 或 r"..."
        if re.search(rf"""r['"].*(?:{combined})""", line, re.IGNORECASE):
            return True

        # 字符串字面量中嵌入了危险模式/标签
        if re.search(rf"""['"][^'"]*(?:{combined})[^'"]*['"]""", line, re.IGNORECASE):
            return True

        return False

    @staticmethod
    def is_comment_about_self(line: str, tag_keywords: str = None) -> bool:
        """
        判断注释行是否是检测器自身规则描述的注释（而非真实的 TODO/FIXME 等）

        例如: "# TODO/FIXME 优先级排序：FIXME/BUG > HACK > TODO > XXX"
        这种注释描述了检测规则本身，不是真实的待办事项。

        Args:
            line: 注释行内容
            tag_keywords: 标签关键词正则（可选）

        Returns:
            True 表示这是检测器自描述注释，应跳过
        """
        kw = tag_keywords or SharedFilter._TAG_KEYWORDS
        stripped = line.strip().lstrip("#").lstrip("/").strip()

        # 如果注释中有多个标签并列（如 "FIXME/BUG > HACK > TODO"），
        # 说明这是规则描述而非真实待办
        tag_count = len(re.findall(rf'\b({kw})\b', stripped, re.IGNORECASE))
        if tag_count >= 2:
            return True

        # 注释中包含 "优先级"、"排序"、"标签"、"正则"、"模式" 等描述性词汇
        if re.search(r'(?:优先级|排序|标签|正则|模式|pattern|priority|severity|rule|规则)', stripped, re.IGNORECASE):
            return True

        return False

    @staticmethod
    def is_placeholder_xxx(line: str) -> bool:
        """
        判断注释行中的 "xxx" 是否是小写占位符（而非真实的 XXX 标记）

        例如: "# 如 request.api_key, cfg.xxx" 中的 "xxx" 是占位符
              "# 推断上游：xxx的分析助理" 中的 "xxx" 是占位符

        Args:
            line: 注释行内容

        Returns:
            True 表示这是占位符，应跳过
        """
        stripped = line.strip().lstrip("#").lstrip("/").strip()

        # 如果 "xxx" 出现在引号中，或作为示例占位符
        # 模式: "...xxx..." 或 cfg.xxx 或 "xxx" 或 xxx的
        if re.search(r'["\']xxx["\']|\.xxx\b|xxx[的之]|如.*xxx|xxx.*占位|xxx.*示例|xxx.*placeholder', stripped, re.IGNORECASE):
            return True

        # 如果 "xxx" 作为占位符且周围没有其他大写的 TODO/FIXME 标签
        if re.search(r'\bxxx\b', stripped) and not re.search(r'\b(?:TODO|FIXME|HACK|BUG)\b', stripped):
            return True

        return False

    # ─── 跨行 try-except 检测 ──────────────────────────────────────

    @staticmethod
    def is_in_try_block(lines: List[str], line_idx: int) -> bool:
        """
        检查指定行是否在 try-except 块中（跨行检测）

        Args:
            lines: 文件内容按行分割的列表
            line_idx: 0-based 行索引

        Returns:
            True 表示该行在 try-except 块中
        """
        current_indent = len(lines[line_idx]) - len(lines[line_idx].lstrip())

        # 向前查找 try:（最多 15 行）
        for j in range(line_idx - 1, max(line_idx - 16, -1), -1):
            prev_line = lines[j].rstrip()
            if not prev_line or prev_line.strip().startswith('#'):
                continue
            prev_indent = len(prev_line) - len(prev_line.lstrip())
            if prev_indent <= current_indent and re.match(r'\s*try\s*:\s*$', prev_line):
                return True
            if prev_indent < current_indent and re.match(r'\s*(?:def|class)\b', prev_line):
                break

        # 向后查找 except:（最多 20 行）
        for j in range(line_idx + 1, min(line_idx + 21, len(lines))):
            next_line = lines[j].rstrip()
            if not next_line or next_line.strip().startswith('#'):
                continue
            next_indent = len(next_line) - len(next_line.lstrip())
            if next_indent <= current_indent and re.match(r'\s*except\b', next_line):
                return True
            if next_indent < current_indent and re.match(r'\s*(?:def|class)\b', next_line):
                break

        return False

    # ─── 综合检测 ──────────────────────────────────────────────────

    @staticmethod
    def should_skip_line(lines: List[str], line_idx: int,
                         docstring_lines: Set[int] = None,
                         check_pattern_def: bool = False,
                         pattern_keywords: str = None) -> bool:
        """
        综合判断是否应跳过某行的检测

        这是一个便捷方法，组合了多个过滤逻辑。

        Args:
            lines: 文件内容按行分割的列表
            line_idx: 0-based 行索引
            docstring_lines: 文档字符串行号集合（可选）
            check_pattern_def: 是否检查规则定义行
            pattern_keywords: 规则定义行关键词（可选）

        Returns:
            True 表示应跳过此行的检测
        """
        stripped = lines[line_idx].strip()

        # 跳过空行
        if not stripped:
            return True

        # 跳过文档字符串
        if docstring_lines and (line_idx + 1) in docstring_lines:
            return True

        # 跳过注释（大部分检测器都用不到的注释行）
        if stripped.startswith("#") or stripped.startswith("//"):
            return True

        # 跳过规则定义行
        if check_pattern_def and SharedFilter.is_pattern_def_line(stripped, pattern_keywords):
            return True

        return False

    # ─── Cache 集成 ─────────────────────────────────────────────────

    @staticmethod
    def load_cache(project_path: str):
        """
        从 cache/ 加载项目专属的硬编码优化数据。

        在每次扫描前调用，确保使用最新的缓存白名单。
        调用后，is_magic_whitelisted / is_security_whitelisted 等方法生效。
        """
        from core.cache_manager import cache_manager
        cache_manager.load_hardcoded(project_path)

    @staticmethod
    def is_magic_whitelisted(value, file_path: str = "") -> bool:
        """检查魔法数字是否在 cache 白名单中"""
        from core.cache_manager import cache_manager
        return cache_manager.is_magic_whitelisted(value, file_path)

    @staticmethod
    def is_security_whitelisted(rule_id: str, file_path: str = "", line: int = 0) -> bool:
        """检查安全规则是否在 cache 白名单中"""
        from core.cache_manager import cache_manager
        return cache_manager.is_security_whitelisted(rule_id, file_path, line)

    @staticmethod
    def is_complexity_exempted(function_name: str, file_path: str = "") -> bool:
        """检查函数是否在 cache 复杂度豁免列表中"""
        from core.cache_manager import cache_manager
        return cache_manager.is_complexity_exempted(function_name, file_path)

    @staticmethod
    def is_naming_exempted(name: str) -> bool:
        """检查命名是否在 cache 豁免列表中"""
        from core.cache_manager import cache_manager
        return cache_manager.is_naming_exempted(name)

    @staticmethod
    def is_integrity_whitelisted(category: str, file_path: str = "", line: int = 0) -> bool:
        """检查完整性检查条目是否在 cache 白名单中"""
        from core.cache_manager import cache_manager
        return cache_manager.is_integrity_whitelisted(category, file_path, line)

    @staticmethod
    def is_resource_gap_whitelisted(category: str, item: str, file_path: str = "") -> bool:
        """检查资源缺口条目是否在 cache 白名单中"""
        from core.cache_manager import cache_manager
        return cache_manager.is_resource_gap_whitelisted(category, item, file_path)

    @staticmethod
    def is_blind_spot_whitelisted(category: str, item: str, file_path: str = "") -> bool:
        """检查盲区检测条目是否在 cache 白名单中"""
        from core.cache_manager import cache_manager
        return cache_manager.is_blind_spot_whitelisted(category, item, file_path)

    @staticmethod
    def is_analysis_whitelisted(category: str, file_path: str = "") -> bool:
        """检查项目分析条目是否在 cache 白名单中"""
        from core.cache_manager import cache_manager
        return cache_manager.is_analysis_whitelisted(category, file_path)

    @staticmethod
    def is_simplify_whitelisted(category: str, function_name: str, file_path: str = "") -> bool:
        """检查简化建议条目是否在 cache 白名单中"""
        from core.cache_manager import cache_manager
        return cache_manager.is_simplify_whitelisted(category, function_name, file_path)

    @staticmethod
    def is_junk_whitelisted(category: str, file_path: str = "") -> bool:
        """检查垃圾文件条目是否在 cache 白名单中"""
        from core.cache_manager import cache_manager
        return cache_manager.is_junk_whitelisted(category, file_path)

    @staticmethod
    def is_sca_whitelisted(package: str, cve_id: str = "") -> bool:
        """检查SCA扫描条目是否在 cache 白名单中"""
        from core.cache_manager import cache_manager
        return cache_manager.is_sca_whitelisted(package, cve_id)

    @staticmethod
    def is_business_analysis_whitelisted(entity_type: str, name: str = "") -> bool:
        """检查业务分析条目是否在 cache 白名单中"""
        from core.cache_manager import cache_manager
        return cache_manager.is_business_analysis_whitelisted(entity_type, name)

    @staticmethod
    def is_innovation_gap_whitelisted(module: str, pattern: str = "") -> bool:
        """检查创新缺口条目是否在 cache 白名单中"""
        from core.cache_manager import cache_manager
        return cache_manager.is_innovation_gap_whitelisted(module, pattern)
