# -*- coding: utf-8 -*-
"""
Prompt 抽取器：从 Python 代码中识别并提取 Prompt 模板

设计原则：
1. 通用性 —— 不硬编码任何项目特定的角色名或目录结构
2. AST 优先 —— 用 Python AST 解析变量赋值，正则作为补充
3. 开源友好 —— 零外部依赖，纯 Python 标准库

提取策略：
- 策略 A：AST 扫描模块级字符串常量（变量名含 prompt/system/role 关键词）
- 策略 B：正则扫描内联 f-string / 字符串字面量（含角色定义模式）
- 策略 C：正则扫描函数调用中的 prompt 参数
"""

import ast
import os
import re
import json
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass, field
from pathlib import Path

from loguru import logger


# ═══════════════════════════════════════════════════════════════
# 数据模型
# ═══════════════════════════════════════════════════════════════

@dataclass
class ExtractedPrompt:
    """从代码中抽取的 Prompt 模板"""
    # ── 来源信息 ──
    file_path: str                    # 源文件路径
    line_start: int                   # 起始行号
    line_end: int                     # 结束行号
    variable_name: str = ""           # 变量名（如 XIAOYAN_SYSTEM）
    
    # ── 内容信息 ──
    content: str = ""                 # prompt 完整内容（前 3000 字符）
    content_hash: str = ""            # 内容 SHA256（用于去重）
    template_format: str = "fstring"  # "fstring" | "triple_quote" | "concatenation"
    variables: List[str] = field(default_factory=list)  # 提取的模板变量
    
    # ── 分类信息 ──
    prompt_type: str = "unknown"      # "system" | "user" | "assistant" | "unknown"
    role_pattern: str = ""            # 匹配到的角色定义模式
    role_name: str = ""               # 从 prompt 中初步提取的角色名
    role_description: str = ""        # 角色描述（前 200 字符）
    
    # ── 元信息 ──
    source_module: str = ""           # 所属模块（顶层目录名）
    is_llm_prompt: bool = False       # 是否确认为 LLM prompt


@dataclass
class PromptExtractionResult:
    """Prompt 抽取结果"""
    project_path: str = ""
    total_files_scanned: int = 0
    total_prompts_found: int = 0
    prompts: List[ExtractedPrompt] = field(default_factory=list)
    
    # 统计
    role_patterns: Dict[str, int] = field(default_factory=dict)  # 角色模式 → 出现次数
    modules: Dict[str, int] = field(default_factory=dict)        # 模块 → prompt 数量


# ═══════════════════════════════════════════════════════════════
# 角色定义模式（通用正则，不依赖特定项目）
# ═══════════════════════════════════════════════════════════════

# 这些正则是通用的 prompt 角色定义模式，适用于各种项目
ROLE_PATTERNS = [
    # 模式 A：昵称化角色 —— 你是「名字」，xxx
    (r'你是[「『]([^」』]*)[」』][，,\s]*([^。\n]{0,80})', 'nickname_role'),
    # 模式 B：标签化角色 —— 【角色】你是xxx
    (r'【角色】\s*你是[「『]?([^」』\n]{1,50})[」』]?', 'tag_role'),
    # 模式 C：职能化角色 —— 你是/你是一位/你是一个 xxx
    (r'你是[一]?[位个]?\s*([^，。\n]{2,50}?)(?:[，,。\.\n]|$)', 'function_role'),
    # 模式 D：英文角色 —— You are a/an xxx
    (r'You are an?\s+([^,.\\n]{2,60})', 'english_role'),
    # 模式 E：角色标签 —— Role: xxx 或 ## Role
    (r'(?:^|\n)\s*(?:#+\s*)?[Rr]ole\s*[:：]\s*([^\n]{1,80})', 'role_label'),
]

# 变量名中包含这些关键词的，很可能是 prompt 变量
PROMPT_VAR_KEYWORDS = [
    'prompt', 'system', 'SYSTEM', 'user_prompt', 'USER_PROMPT',
    'assistant_prompt', 'instruction', 'INSTRUCTION', 'template',
    'TEMPLATE', 'slogan', 'SLOGAN', 'headline', 'HEADLINE',
    'coach', 'COACH', 'analyst', 'ANALYST', 'reviewer', 'REVIEWER',
    'verdict', 'VERDICT', 'canvas', 'CANVAS', 'guard', 'GUARD',
    'router', 'ROUTER', 'advice', 'ADVICE', 'guide', 'GUIDE',
]

# 内容中包含这些关键词的，很可能是 LLM prompt
LLM_PROMPT_CONTENT_KEYWORDS = [
    '你是', 'You are', '你的任务', 'Your task', '输出格式',
    'output format', 'JSON', 'Markdown', 'system prompt',
    'temperature', 'max_tokens', 'role', '角色',
]


# ═══════════════════════════════════════════════════════════════
# 核心抽取逻辑
# ═══════════════════════════════════════════════════════════════

class PromptExtractor:
    """从 Python 项目中抽取 Prompt 模板"""
    
    def __init__(self, llm_client=None):
        self.llm = llm_client
        self._seen_hashes = set()  # 内容去重
    
    def extract_from_project(self, project_path: str) -> PromptExtractionResult:
        """
        从整个项目中抽取所有 Prompt 模板
        
        Args:
            project_path: 项目根目录
        
        Returns:
            PromptExtractionResult: 抽取结果
        """
        result = PromptExtractionResult(project_path=project_path)
        
        py_files = list(Path(project_path).rglob("*.py"))
        result.total_files_scanned = len(py_files)
        
        for py_file in py_files:
            # 跳过虚拟环境和缓存
            if any(skip in str(py_file) for skip in ['__pycache__', '.venv', 'venv', 'node_modules', '.git']):
                continue
            
            try:
                prompts = self._extract_from_file(str(py_file), project_path)
                for p in prompts:
                    if p.content_hash not in self._seen_hashes:
                        self._seen_hashes.add(p.content_hash)
                        result.prompts.append(p)
                        
                        # 统计
                        if p.role_pattern:
                            result.role_patterns[p.role_pattern] = \
                                result.role_patterns.get(p.role_pattern, 0) + 1
                        result.modules[p.source_module] = \
                            result.modules.get(p.source_module, 0) + 1
            except Exception as e:
                logger.debug(f"[PromptExtractor] 跳过 {py_file}: {e}")
        
        result.total_prompts_found = len(result.prompts)
        logger.info(f"[PromptExtractor] 抽取完成: {result.total_files_scanned} 文件 → "
                    f"{result.total_prompts_found} 个 Prompt, "
                    f"角色模式: {result.role_patterns}")
        return result
    
    def _extract_from_file(self, file_path: str, project_path: str) -> List[ExtractedPrompt]:
        """从单个文件中抽取 Prompt"""
        prompts = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                source = f.read()
        except Exception:
            return prompts
        
        # 策略 A：AST 扫描模块级变量赋值
        ast_prompts = self._extract_ast_assignments(file_path, source, project_path)
        prompts.extend(ast_prompts)
        
        # 策略 B：正则扫描内联字符串（AST 可能漏掉函数内的字符串）
        # 只有当 AST 没有找到足够多的 prompt 时才启用（避免重复）
        if len(prompts) < 3:
            regex_prompts = self._extract_regex_strings(file_path, source, project_path)
            # 去重：已经通过 AST 找到的变量不再重复
            ast_names = {p.variable_name for p in prompts if p.variable_name}
            for rp in regex_prompts:
                if rp.variable_name not in ast_names:
                    prompts.append(rp)
        
        return prompts
    
    def _extract_ast_assignments(
        self, file_path: str, source: str, project_path: str
    ) -> List[ExtractedPrompt]:
        """用 AST 解析模块级字符串常量赋值"""
        prompts = []
        
        try:
            tree = ast.parse(source)
        except SyntaxError:
            return prompts
        
        # 获取源代码行号映射
        lines = source.split('\n')
        
        # 只看模块级的赋值语句
        for node in ast.iter_child_nodes(tree):
            if not isinstance(node, ast.Assign):
                continue
            
            # 获取变量名
            var_names = []
            for target in node.targets:
                if isinstance(target, ast.Name):
                    var_names.append(target.id)
            
            if not var_names:
                continue
            
            var_name = var_names[0]
            
            # 检查变量名是否包含 prompt 关键词
            is_prompt_var = any(kw.lower() in var_name.lower() for kw in PROMPT_VAR_KEYWORDS)
            
            # 获取赋值的值
            value = node.value
            
            # 情况 1：三引号字符串
            if isinstance(value, ast.Constant) and isinstance(value.value, str):
                content = value.value
                if not is_prompt_var and len(content) < 200:
                    continue  # 太短的字符串且变量名不像 prompt，跳过
                
                if self._is_likely_prompt(content):
                    is_prompt_var = True
                
                if is_prompt_var:
                    prompt = self._build_prompt(
                        file_path=file_path,
                        source=source,
                        lines=lines,
                        var_name=var_name,
                        content=content,
                        line_start=node.lineno,
                        project_path=project_path,
                    )
                    prompts.append(prompt)
            
            # 情况 2：f-string（ast.JoinedStr）
            elif isinstance(value, ast.JoinedStr):
                # 提取 f-string 的内容
                content_parts = []
                variables = []
                for part in value.values:
                    if isinstance(part, ast.Constant):
                        content_parts.append(str(part.value))
                    elif isinstance(part, ast.FormattedValue):
                        content_parts.append(f"{{{self._get_formatted_value_repr(part)}}}")
                        variables.append(self._get_formatted_value_repr(part))
                
                content = ''.join(content_parts)
                if is_prompt_var or self._is_likely_prompt(content):
                    prompt = self._build_prompt(
                        file_path=file_path,
                        source=source,
                        lines=lines,
                        var_name=var_name,
                        content=content,
                        line_start=node.lineno,
                        project_path=project_path,
                        template_format="fstring",
                        variables=variables,
                    )
                    prompts.append(prompt)
            
            # 情况 3：字符串拼接（ast.BinOp with Add）
            elif isinstance(value, ast.BinOp) and isinstance(value.op, ast.Add):
                content = self._extract_concat_string(value)
                if content and (is_prompt_var or self._is_likely_prompt(content)):
                    prompt = self._build_prompt(
                        file_path=file_path,
                        source=source,
                        lines=lines,
                        var_name=var_name,
                        content=content,
                        line_start=node.lineno,
                        project_path=project_path,
                        template_format="concatenation",
                    )
                    prompts.append(prompt)
        
        return prompts
    
    def _extract_regex_strings(
        self, file_path: str, source: str, project_path: str
    ) -> List[ExtractedPrompt]:
        """用正则扫描内联字符串（补充 AST 可能漏掉的）"""
        prompts = []
        lines = source.split('\n')
        
        # 匹配 f"""...""" 或 """...""" 包含角色定义的长字符串
        # 使用更宽松的匹配：查找所有包含 "你是" 或 "You are" 的长字符串
        for match in re.finditer(
            r'(?:[a-zA-Z_]\w*\s*=\s*)?'
            r'(?:f?"""|\'\'\')'
            r'(.+?)'
            r'(?:"""|\'\'\')',
            source, re.DOTALL
        ):
            content = match.group(1)
            if len(content) < 150:
                continue
            if not self._is_likely_prompt(content):
                continue
            
            # 计算行号
            pos = match.start()
            line_start = source[:pos].count('\n') + 1
            
            # 提取变量名（如果有）
            var_name = ""
            prefix = source[max(0, pos - 80):pos]
            var_match = re.search(r'([A-Z_][A-Z_0-9]{2,})\s*=\s*$', prefix)
            if var_match:
                var_name = var_match.group(1)
            
            prompt = self._build_prompt(
                file_path=file_path,
                source=source,
                lines=lines,
                var_name=var_name,
                content=content,
                line_start=line_start,
                project_path=project_path,
            )
            prompts.append(prompt)
        
        return prompts
    
    def _build_prompt(
        self,
        file_path: str,
        source: str,
        lines: List[str],
        var_name: str,
        content: str,
        line_start: int,
        project_path: str,
        template_format: str = "triple_quote",
        variables: List[str] = None,
    ) -> ExtractedPrompt:
        """构建 ExtractedPrompt 对象"""
        import hashlib
        
        # 计算内容哈希
        content_hash = hashlib.sha256(content.encode('utf-8', errors='replace')).hexdigest()[:16]
        
        # 截断内容
        display_content = content[:3000]
        
        # 计算结束行号
        line_end = line_start + content.count('\n')
        
        # 提取变量
        if variables is None:
            variables = re.findall(r'\{(\w+)\}', content)
            # 去重保序
            seen = set()
            variables = [v for v in variables if not (v in seen or seen.add(v))]
        
        # 分类角色模式
        role_pattern, role_name, role_description = self._classify_role(content)
        
        # 判断 prompt 类型
        prompt_type = self._classify_prompt_type(var_name, content)
        
        # 确定源模块
        rel_path = os.path.relpath(file_path, project_path)
        rel_normalized = rel_path.replace('\\', '/')
        parts = rel_normalized.split('/')
        # 取第一层目录作为模块名（如果有子目录），否则取父目录名
        if len(parts) >= 2 and parts[0] not in ('.', '..'):
            source_module = parts[0]
        elif len(parts) == 1 and parts[0] not in ('.', '..'):
            source_module = os.path.basename(os.path.dirname(file_path)) or parts[0]
        else:
            source_module = "root"
        
        return ExtractedPrompt(
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            variable_name=var_name,
            content=display_content,
            content_hash=content_hash,
            template_format=template_format,
            variables=variables,
            prompt_type=prompt_type,
            role_pattern=role_pattern,
            role_name=role_name,
            role_description=role_description,
            source_module=source_module,
            is_llm_prompt=True,
        )
    
    def _classify_role(self, content: str) -> Tuple[str, str, str]:
        """
        从 prompt 内容中提取角色定义
        
        Returns:
            (role_pattern, role_name, role_description)
        """
        first_500 = content[:500]
        
        for pattern, pattern_name in ROLE_PATTERNS:
            match = re.search(pattern, first_500)
            if match:
                groups = match.groups()
                role_name = groups[0].strip() if groups else ""
                role_desc = groups[1].strip() if len(groups) > 1 else ""
                return pattern_name, role_name, role_desc[:200]
        
        return "", "", ""
    
    def _classify_prompt_type(self, var_name: str, content: str) -> str:
        """根据变量名和内容判断 prompt 类型"""
        var_lower = var_name.lower()
        
        if any(kw in var_lower for kw in ['system', 'instruction', 'guard', 'router']):
            return "system"
        if any(kw in var_lower for kw in ['user', 'human']):
            return "user"
        if any(kw in var_lower for kw in ['assistant', 'ai']):
            return "assistant"
        
        # 从内容推断
        first_200 = content[:200].lower()
        if 'system' in first_200 or '你是' in first_200 or 'you are' in first_200:
            return "system"
        
        return "unknown"
    
    def _is_likely_prompt(self, content: str) -> bool:
        """判断一段文本是否很可能是 LLM prompt"""
        if len(content) < 100:
            return False
        
        # 检查是否包含角色定义或任务描述
        first_500 = content[:500]
        keyword_count = sum(
            1 for kw in LLM_PROMPT_CONTENT_KEYWORDS
            if kw.lower() in first_500.lower()
        )
        
        # 至少匹配 2 个关键词才认为是 prompt
        if keyword_count >= 2:
            return True
        
        # 检查角色模式
        for pattern, _ in ROLE_PATTERNS:
            if re.search(pattern, first_500):
                return True
        
        return False
    
    def _extract_concat_string(self, node) -> Optional[str]:
        """递归提取字符串拼接的内容"""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        elif isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left = self._extract_concat_string(node.left)
            right = self._extract_concat_string(node.right)
            if left is not None and right is not None:
                return left + right
        return None
    
    def _get_formatted_value_repr(self, node) -> str:
        """获取 f-string 中格式化值的字符串表示"""
        if isinstance(node, ast.FormattedValue):
            if isinstance(node.value, ast.Name):
                return node.value.id
            elif isinstance(node.value, ast.Attribute):
                return f"{self._get_formatted_value_repr(node.value)}.{node.value.attr}"
            elif isinstance(node.value, ast.Subscript):
                return f"{self._get_formatted_value_repr(node.value)}[...]"
        elif isinstance(node, ast.Attribute):
            return f"{self._get_formatted_value_repr(node.value)}.{node.attr}" if isinstance(node.value, ast.Name) else str(node.value)
        return "?"
    
    # ═══════════════════════════════════════════════════════════
    # 便捷方法
    # ═══════════════════════════════════════════════════════════
    
    def get_roles_by_module(self, result: PromptExtractionResult) -> Dict[str, List[dict]]:
        """按模块分组角色"""
        roles = {}
        for p in result.prompts:
            if p.role_name:
                module = p.source_module
                if module not in roles:
                    roles[module] = []
                roles[module].append({
                    'name': p.role_name,
                    'pattern': p.role_pattern,
                    'type': p.prompt_type,
                    'variable': p.variable_name,
                    'file': os.path.basename(p.file_path),
                    'description': p.role_description,
                })
        return roles
    
    def get_workflow_roles(self, result: PromptExtractionResult) -> List[dict]:
        """
        获取业务流程中涉及的角色（昵称化角色）
        
        昵称化角色（如「小验」「老商」）通常对应业务流程中的角色分工。
        通过这些角色可以推断业务流程的步骤。
        """
        workflow_roles = []
        for p in result.prompts:
            if p.role_pattern == 'nickname_role' and p.role_name:
                workflow_roles.append({
                    'role_name': p.role_name,
                    'description': p.role_description,
                    'variable': p.variable_name,
                    'module': p.source_module,
                    'file': os.path.basename(p.file_path),
                })
        return workflow_roles
    
    def to_summary(self, result: PromptExtractionResult) -> str:
        """生成可读摘要"""
        lines = []
        lines.append(f"# Prompt 抽取摘要")
        lines.append(f"\n- 扫描文件: {result.total_files_scanned}")
        lines.append(f"- 发现 Prompt: {result.total_prompts_found}")
        lines.append(f"\n## 角色模式分布")
        for pattern, count in sorted(result.role_patterns.items(), key=lambda x: -x[1]):
            lines.append(f"- {pattern}: {count}")
        lines.append(f"\n## 模块分布")
        for module, count in sorted(result.modules.items(), key=lambda x: -x[1]):
            lines.append(f"- {module}: {count}")
        lines.append(f"\n## 角色列表")
        for p in result.prompts:
            if p.role_name:
                lines.append(f"- **{p.role_name}** ({p.role_pattern}) — {p.role_description[:80]}  [{p.source_module}/{os.path.basename(p.file_path)}:{p.line_start}]")
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════
# 便捷函数
# ═══════════════════════════════════════════════════════════════

def extract_prompts(project_path: str, llm_client=None) -> PromptExtractionResult:
    """一键抽取项目中所有 Prompt"""
    extractor = PromptExtractor(llm_client=llm_client)
    return extractor.extract_from_project(project_path)
