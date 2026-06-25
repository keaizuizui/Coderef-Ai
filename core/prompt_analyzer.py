# -*- coding: utf-8 -*-
"""
Prompt 分析器：从 Prompt 中提取角色信息、工作流步骤、输入输出

设计原则：
1. 通用性 —— 不硬编码任何角色名，完全由 LLM 从 prompt 内容中推断
2. 分层分析 —— 先提取角色 → 再提取工作流 → 最后映射业务实体
3. 开源友好 —— 零外部依赖，LLM 调用为可选增强

分析流程：
1. 角色提取：从 system prompt 中提取角色名、职责、方法
2. 工作流提取：从多个 prompt 的步骤描述中重建端到端流程
3. 角色关系：推导角色之间的协作关系（谁产出→谁消费）
4. 业务映射：将角色映射到业务模块
"""

import json
import os
import re
from typing import List, Dict, Optional, Tuple, Any
from dataclasses import dataclass, field

from loguru import logger

from core.prompt_extractor import PromptExtractionResult, ExtractedPrompt


# ═══════════════════════════════════════════════════════════════
# 数据模型
# ═══════════════════════════════════════════════════════════════

@dataclass
class AnalyzedRole:
    """从 Prompt 中分析出的角色"""
    name: str                        # 角色名（如"小验"、"老商"）
    nickname: str = ""               # 昵称（如"小验"）
    description: str = ""            # 角色描述
    responsibility: str = ""         # 核心职责
    methods: List[str] = field(default_factory=list)   # 使用的方法论/框架
    output_format: str = ""          # 输出格式（JSON/Markdown/纯文本）
    prompt_variable: str = ""        # 对应的 prompt 变量名
    source_module: str = ""          # 来源模块
    source_file: str = ""            # 来源文件
    downstream_roles: List[str] = field(default_factory=list)  # 下游角色
    upstream_roles: List[str] = field(default_factory=list)    # 上游角色


@dataclass
class AnalyzedWorkflow:
    """从 Prompt 中分析出的工作流"""
    name: str                        # 流程名称
    module: str = ""                 # 所属模块
    steps: List[Dict[str, str]] = field(default_factory=list)  # 步骤列表
    roles_sequence: List[str] = field(default_factory=list)    # 角色执行顺序
    trigger: str = ""               # 触发条件
    output: str = ""                # 产出物
    entry_role: str = ""            # 入口角色
    exit_role: str = ""             # 出口角色


@dataclass
class PromptAnalysisResult:
    """Prompt 分析结果"""
    project_path: str = ""
    total_prompts: int = 0
    total_roles: int = 0
    total_workflows: int = 0
    
    roles: List[AnalyzedRole] = field(default_factory=list)
    workflows: List[AnalyzedWorkflow] = field(default_factory=list)
    
    # 角色关系图（nickname → role_name）
    nickname_map: Dict[str, str] = field(default_factory=dict)


# ═══════════════════════════════════════════════════════════════
# 核心分析器
# ═══════════════════════════════════════════════════════════════

class PromptAnalyzer:
    """
    从 Prompt 中分析角色和工作流
    
    Args:
        llm_client: LLM 客户端（可选，用于深度分析）
        prompt_result: PromptExtractionResult 抽取结果
    """
    
    def __init__(self, llm_client=None):
        self.llm = llm_client
    
    def analyze(self, prompt_result: PromptExtractionResult) -> PromptAnalysisResult:
        """
        分析 Prompt 抽取结果，提取角色和工作流
        
        分析策略：
        1. 规则层：从 prompt 内容中直接提取角色名、输出格式
        2. LLM 层：用 LLM 推断角色职责、方法论、上下游关系
        3. 合成层：将角色串联成工作流
        """
        result = PromptAnalysisResult(
            project_path=prompt_result.project_path,
            total_prompts=prompt_result.total_prompts_found,
        )
        
        # ── 第一步：规则提取角色基本信息 ──
        roles = self._extract_roles_by_rules(prompt_result)
        result.roles = roles
        
        # ── 第二步：LLM 深度分析（如果有 LLM） ──
        if self.llm and hasattr(self.llm, 'chat_completion'):
            try:
                roles = self._enrich_roles_with_llm(roles, prompt_result)
                result.roles = roles
            except Exception as e:
                logger.warning(f"[PromptAnalyzer] LLM 角色增强失败，使用规则提取结果: {e}")
        
        result.total_roles = len(roles)
        
        # ── 第三步：构建昵称映射 ──
        for r in roles:
            if r.nickname:
                result.nickname_map[r.nickname] = r.name
        
        # ── 第四步：推导角色关系 ──
        roles = self._infer_role_relationships(roles, prompt_result)
        result.roles = roles
        
        # ── 第五步：提取工作流 ──
        if self.llm and hasattr(self.llm, 'chat_completion'):
            try:
                workflows = self._extract_workflows_with_llm(roles, prompt_result)
                result.workflows = workflows
            except Exception as e:
                logger.warning(f"[PromptAnalyzer] LLM 工作流提取失败: {e}")
                workflows = self._extract_workflows_by_rules(roles, prompt_result)
                result.workflows = workflows
        else:
            workflows = self._extract_workflows_by_rules(roles, prompt_result)
            result.workflows = workflows
        
        result.total_workflows = len(result.workflows)
        
        logger.info(f"[PromptAnalyzer] 分析完成: {result.total_roles} 角色, "
                    f"{result.total_workflows} 工作流")
        return result
    
    # ═══════════════════════════════════════════════════════════
    # 规则提取
    # ═══════════════════════════════════════════════════════════
    
    def _extract_roles_by_rules(self, prompt_result: PromptExtractionResult) -> List[AnalyzedRole]:
        """用规则从 prompt 中提取角色基本信息"""
        roles = []
        seen_names = set()
        
        # 只处理 system 类型的 prompt（含角色定义）
        system_prompts = [p for p in prompt_result.prompts
                         if p.prompt_type == 'system' and p.role_name]
        
        for p in system_prompts:
            name = p.role_name.strip()
            if not name or name in seen_names:
                continue
            seen_names.add(name)
            
            # 提取昵称
            nickname = ""
            if p.role_pattern == 'nickname_role':
                nickname = name
            
            # 提取核心职责（从 prompt 前 500 字符中提取 "你的任务" 或 "你的职责" 开头的内容）
            responsibility = self._extract_responsibility(p.content)
            
            # 提取方法论/框架
            methods = self._extract_methods(p.content)
            
            # 提取输出格式
            output_format = self._extract_output_format(p.content)
            
            role = AnalyzedRole(
                name=name,
                nickname=nickname,
                description=p.role_description,
                responsibility=responsibility,
                methods=methods,
                output_format=output_format,
                prompt_variable=p.variable_name,
                source_module=p.source_module,
                source_file=os.path.basename(p.file_path) if hasattr(os, 'path') else p.file_path.split('/')[-1] if '/' in p.file_path else p.file_path.split('\\')[-1],
            )
            roles.append(role)
        
        return roles
    
    def _extract_responsibility(self, content: str) -> str:
        """从 prompt 内容中提取核心职责"""
        # 匹配 "你的任务" / "你的职责" / "负责" 等模式
        patterns = [
            r'你的任务是?[：:]\s*(.+?)(?:。|\n)',
            r'你的职责是?[：:]\s*(.+?)(?:。|\n)',
            r'专门负责(.+?)(?:。|\n)',
            r'负责(.+?)(?:。|\n)',
        ]
        for pattern in patterns:
            match = re.search(pattern, content[:800])
            if match:
                return match.group(1).strip()[:200]
        return ""
    
    def _extract_methods(self, content: str) -> List[str]:
        """从 prompt 中提取方法论/框架名称"""
        methods = []
        # 常见方法论模式
        method_patterns = [
            r'[=＝]{2,}\s*(.+?)\s*[=＝]{2,}',  # === 方法论名 ===
            r'【(.+?)】',                         # 【方法论名】
            r'##\s+(.+?)(?:\n|$)',               # ## 标题
            r'第[一二三四五六七八九十]步[：:]\s*(.+?)(?:\n|。|$)',  # 步骤标题
        ]
        for pattern in method_patterns:
            for match in re.finditer(pattern, content[:2000]):
                method = match.group(1).strip()
                if 2 <= len(method) <= 30 and method not in methods:
                    methods.append(method)
        
        return methods[:12]
    
    def _extract_output_format(self, content: str) -> str:
        """从 prompt 中提取输出格式要求"""
        content_lower = content[:1000].lower()
        if 'json' in content_lower:
            return 'JSON'
        if 'markdown' in content_lower:
            return 'Markdown'
        if '纯文本' in content[:1000] or 'plain text' in content_lower:
            return '纯文本'
        if '表格' in content[:1000] or 'table' in content_lower:
            return '表格'
        return '未指定'
    
    # ═══════════════════════════════════════════════════════════
    # LLM 增强
    # ═══════════════════════════════════════════════════════════
    
    def _enrich_roles_with_llm(
        self, roles: List[AnalyzedRole], prompt_result: PromptExtractionResult
    ) -> List[AnalyzedRole]:
        """用 LLM 增强角色分析"""
        # 构建角色列表摘要
        role_summaries = []
        for r in roles:
            # 找到对应的完整 prompt
            full_prompt = ""
            for p in prompt_result.prompts:
                if p.role_name == r.name and p.prompt_type == 'system':
                    full_prompt = p.content[:1200]
                    break
            
            role_summaries.append({
                'name': r.name,
                'nickname': r.nickname,
                'prompt_excerpt': full_prompt[:800] if full_prompt else r.description,
                'module': r.source_module,
            })
        
        if not role_summaries:
            return roles
        
        # 限制数量，避免 token 过多
        role_summaries = role_summaries[:20]
        
        prompt_text = f"""分析以下从代码中提取的 AI Agent 角色定义。每个角色都来自 system prompt。

角色列表：
{json.dumps(role_summaries, ensure_ascii=False, indent=2)}

请对每个角色进行分析，返回 JSON 格式：
```json
[
  {{
    "name": "角色名",
    "responsibility": "核心职责（一句话，20字以内）",
    "methods": ["使用的方法论1", "方法2"],
    "upstream": "上游角色名（谁把结果传给这个角色，没有则填null）",
    "downstream": "下游角色名（这个角色的结果传给谁，没有则填null）"
  }}
]
```

注意：
- 上游/下游关系通过角色描述中的工作流推断（如"老商的分析助理"暗示上游是老商）
- 方法论指角色使用的分析框架（如"四步校验法"、"行动思考画布"、"六顶思考帽"）
- 如果 prompt 中明确有"小验→小张→老商"这样的关系，请利用它"""
        
        try:
            response = self.llm.chat_completion([
                {"role": "system", "content": "你是一个代码分析专家。请仅返回JSON格式。"},
                {"role": "user", "content": prompt_text}
            ])
            
            # 提取 JSON
            json_match = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL)
            if not json_match:
                json_match = re.search(r'\[.*\]', response, re.DOTALL)
            
            if json_match:
                enrichments = json.loads(json_match.group(1) if json_match.lastindex else json_match.group())
                
                # 合并到角色
                for enrichment in enrichments:
                    for r in roles:
                        if r.name == enrichment.get('name'):
                            if enrichment.get('responsibility') and not r.responsibility:
                                r.responsibility = enrichment['responsibility']
                            if enrichment.get('methods'):
                                r.methods = enrichment['methods']
                            if enrichment.get('upstream'):
                                r.upstream_roles = [enrichment['upstream']]
                            if enrichment.get('downstream'):
                                r.downstream_roles = [enrichment['downstream']]
                            break
        except Exception as e:
            logger.warning(f"[PromptAnalyzer] LLM 角色增强调用失败: {e}")
        
        return roles
    
    # ═══════════════════════════════════════════════════════════
    # 角色关系推断
    # ═══════════════════════════════════════════════════════════
    
    def _infer_role_relationships(
        self, roles: List[AnalyzedRole], prompt_result: PromptExtractionResult
    ) -> List[AnalyzedRole]:
        """推断角色之间的上下游关系"""
        # 从 prompt 内容中推断关系
        for p in prompt_result.prompts:
            if not p.role_name:
                continue
            
            content_first_500 = p.content[:500]
            
            # 查找当前角色
            current_role = None
            for r in roles:
                if r.name == p.role_name:
                    current_role = r
                    break
            if not current_role:
                continue
            
            # 推断上游："xxx的分析助理" → 上游是 xxx
            upstream_patterns = [
                r'([^，。\n]{1,10})的(?:分析)?助理',
                r'([^，。\n]{1,10})的(.{1,10})',
                r'承接([^，。\n]{1,10})',
            ]
            for pattern in upstream_patterns:
                match = re.search(pattern, content_first_500)
                if match:
                    upstream = match.group(1).strip()
                    if upstream != current_role.name and upstream not in current_role.upstream_roles:
                        current_role.upstream_roles.append(upstream)
            
            # 推断下游："调度"、"安排"、"传给" 后面的角色
            downstream_patterns = [
                r'调度[「『]?([^」』，。\n]{1,10})[」』]?',
                r'安排[「『]?([^」』，。\n]{1,10})[」』]?',
                r'调用[「『]?([^」』，。\n]{1,10})[」』]?',
            ]
            for pattern in downstream_patterns:
                match = re.search(pattern, content_first_500)
                if match:
                    downstream = match.group(1).strip()
                    if downstream != current_role.name and downstream not in current_role.downstream_roles:
                        current_role.downstream_roles.append(downstream)
        
        return roles
    
    # ═══════════════════════════════════════════════════════════
    # 工作流提取
    # ═══════════════════════════════════════════════════════════
    
    def _extract_workflows_with_llm(
        self, roles: List[AnalyzedRole], prompt_result: PromptExtractionResult
    ) -> List[AnalyzedWorkflow]:
        """用 LLM 从角色关系中提取工作流"""
        # 收集角色关系
        role_relations = []
        for r in roles:
            role_relations.append({
                'name': r.name,
                'nickname': r.nickname,
                'responsibility': r.responsibility,
                'upstream': r.upstream_roles,
                'downstream': r.downstream_roles,
                'module': r.source_module,
            })
        
        if not role_relations:
            return []
        
        prompt_text = f"""根据以下 AI Agent 角色定义和关系，推导出端到端的业务流程（工作流）。

角色列表：
{json.dumps(role_relations, ensure_ascii=False, indent=2)}

请返回 JSON 格式的工作流列表：
```json
[
  {{
    "name": "工作流名称",
    "module": "所属模块",
    "trigger": "触发条件",
    "output": "产出物",
    "roles_sequence": ["角色1", "角色2", "角色3"],
    "steps": [
      {{"order": 1, "role": "角色1", "action": "具体做什么"}},
      {{"order": 2, "role": "角色2", "action": "具体做什么"}}
    ]
  }}
]
```

注意：
- 如果一个模块有多个角色，它们可能组成一个工作流
- 上下游关系定义了角色的执行顺序
- 每个工作流应该 >= 3 步"""
        
        try:
            response = self.llm.chat_completion([
                {"role": "system", "content": "你是一个业务流程分析专家。请仅返回JSON格式。"},
                {"role": "user", "content": prompt_text}
            ])
            
            json_match = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL)
            if not json_match:
                json_match = re.search(r'\[.*\]', response, re.DOTALL)
            
            if json_match:
                data = json.loads(json_match.group(1) if json_match.lastindex else json_match.group())
                workflows = []
                for w in data:
                    workflows.append(AnalyzedWorkflow(
                        name=w.get('name', ''),
                        module=w.get('module', ''),
                        trigger=w.get('trigger', ''),
                        output=w.get('output', ''),
                        roles_sequence=w.get('roles_sequence', []),
                        steps=w.get('steps', []),
                        entry_role=w.get('roles_sequence', [''])[0] if w.get('roles_sequence') else '',
                        exit_role=w.get('roles_sequence', ['', ''])[-1] if w.get('roles_sequence') else '',
                    ))
                return workflows
        except Exception as e:
            logger.warning(f"[PromptAnalyzer] LLM 工作流提取失败: {e}")
        
        return self._extract_workflows_by_rules(roles, prompt_result)
    
    def _extract_workflows_by_rules(
        self, roles: List[AnalyzedRole], prompt_result: PromptExtractionResult
    ) -> List[AnalyzedWorkflow]:
        """用规则从角色关系中提取工作流（降级方案）"""
        workflows = []
        
        # 按模块分组角色
        module_roles: Dict[str, List[AnalyzedRole]] = {}
        for r in roles:
            module = r.source_module if r.source_module != 'root' else '其他'
            if module not in module_roles:
                module_roles[module] = []
            module_roles[module].append(r)
        
        # 为每个有多角色的模块创建工作流
        for module, mod_roles in module_roles.items():
            if len(mod_roles) < 2:
                continue
            
            # 按上下游关系排序
            ordered = self._topological_sort(mod_roles)
            
            if len(ordered) >= 2:
                steps = [
                    {
                        'order': i + 1,
                        'role': r.name,
                        'action': r.responsibility or r.description or f'{r.name}的职责',
                    }
                    for i, r in enumerate(ordered)
                ]
                
                # 如果步骤太少，从 prompt 中补充步骤
                steps = self._enrich_steps_from_prompts(steps, ordered, prompt_result)
                
                workflows.append(AnalyzedWorkflow(
                    name=f"{module}工作流",
                    module=module,
                    trigger=f"用户发起 {module} 请求",
                    output=f"{module} 产出结果",
                    roles_sequence=[r.name for r in ordered],
                    steps=steps,
                    entry_role=ordered[0].name,
                    exit_role=ordered[-1].name,
                ))
        
        return workflows
    
    def _topological_sort(self, roles: List[AnalyzedRole]) -> List[AnalyzedRole]:
        """简单的拓扑排序（基于上下游关系）"""
        # 构建入度
        in_degree = {r.name: len(r.upstream_roles) for r in roles}
        name_to_role = {r.name: r for r in roles}
        
        # 找到入口（入度为 0）
        queue = [r for r in roles if in_degree[r.name] == 0]
        result = []
        
        while queue:
            current = queue.pop(0)
            result.append(current)
            
            for downstream_name in current.downstream_roles:
                if downstream_name in in_degree:
                    in_degree[downstream_name] -= 1
                    if in_degree[downstream_name] == 0:
                        if downstream_name in name_to_role:
                            queue.append(name_to_role[downstream_name])
        
        # 如果还有未处理的，追加到末尾
        for r in roles:
            if r not in result:
                result.append(r)
        
        return result
    
    def _enrich_steps_from_prompts(
        self,
        steps: List[Dict],
        roles: List[AnalyzedRole],
        prompt_result: PromptExtractionResult,
    ) -> List[Dict]:
        """从 prompt 内容中补充步骤描述"""
        for step in steps:
            role_name = step.get('role', '')
            
            # 找到对应角色的完整 prompt
            for p in prompt_result.prompts:
                if p.role_name == role_name and p.prompt_type == 'system':
                    # 提取步骤描述
                    step_patterns = [
                        r'第[一二三四五六七八九十]+步[：:]\s*(.+?)(?:\n|。|$)',
                        r'步骤\s*\d+[：:]\s*(.+?)(?:\n|。|$)',
                        r'Step\s*\d+[：:]\s*(.+?)(?:\n|。|$)',
                    ]
                    for pattern in step_patterns:
                        matches = re.findall(pattern, p.content[:2000])
                        if matches:
                            step['action'] = '; '.join(matches[:3])
                            break
                    break
        
        return steps
    
    # ═══════════════════════════════════════════════════════════
    # 便捷方法
    # ═══════════════════════════════════════════════════════════
    
    def to_summary(self, result: PromptAnalysisResult) -> str:
        """生成可读摘要"""
        lines = []
        lines.append(f"# Prompt 分析摘要")
        lines.append(f"\n- 总 Prompt: {result.total_prompts}")
        lines.append(f"- 识别角色: {result.total_roles}")
        lines.append(f"- 识别工作流: {result.total_workflows}")
        
        if result.roles:
            lines.append(f"\n## 角色列表")
            for r in result.roles:
                nickname_str = f"（昵称：{r.nickname}）" if r.nickname else ""
                lines.append(f"\n### {r.name}{nickname_str}")
                if r.responsibility:
                    lines.append(f"- 职责：{r.responsibility}")
                if r.methods:
                    lines.append(f"- 方法论：{', '.join(r.methods[:5])}")
                if r.upstream_roles:
                    lines.append(f"- 上游：{', '.join(r.upstream_roles)}")
                if r.downstream_roles:
                    lines.append(f"- 下游：{', '.join(r.downstream_roles)}")
                lines.append(f"- 来源：{r.source_module}/{r.source_file} ({r.prompt_variable})")
        
        if result.workflows:
            lines.append(f"\n## 工作流列表")
            for w in result.workflows:
                lines.append(f"\n### {w.name}")
                lines.append(f"- 触发：{w.trigger}")
                lines.append(f"- 产出：{w.output}")
                lines.append(f"- 角色序列：{' → '.join(w.roles_sequence)}")
                if w.steps:
                    lines.append(f"- 步骤：")
                    for step in w.steps:
                        lines.append(f"  {step.get('order', '?')}. {step.get('role', '?')}：{step.get('action', '')[:80]}")
        
        return "\n".join(lines)


# ═══════════════════════════════════════════════════════════════
# 便捷函数
# ═══════════════════════════════════════════════════════════════

def analyze_prompts(
    prompt_result: PromptExtractionResult,
    llm_client=None,
) -> PromptAnalysisResult:
    """一键分析 Prompt"""
    analyzer = PromptAnalyzer(llm_client=llm_client)
    return analyzer.analyze(prompt_result)
