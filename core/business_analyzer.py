# -*- coding: utf-8 -*-
"""
通用业务分析引擎
==================
解决传统代码分析报告「只有技术细节、缺乏业务理解」的痛点。

核心设计理念:
1. 通用性 —— 不硬编码任何项目特定知识，对任意代码库都能动态发现业务概念
2. 自学习 —— 每次分析完成后自我评估，发现不足后自动优化分析方案再跑一遍
3. 多层级 —— 从文件结构 → 技术架构 → 业务能力 → 用户角色 → 业务流程 → 跨端差异，
           逐层深入到非程序员也能看懂的业务全景图

工作管线 (Pipeline):
  Stage 0: 结构扫描  (依赖现有 CodeAnalyzer)
  Stage 1: 业务概念发现 (LLM 从类/函数/docstring 推断业务名词)
  Stage 2: 角色与工作流发现 (LLM 分析调用链和模式，提取业务流)
  Stage 3: 跨端与角色差异分析 (LLM 对比 Web/GUI 差异、角色权限差异)
  Stage 4: 自评估 (检查输出质量)
  Stage 5: 自改进 (如果质量不足，修正分析策略后重跑 Stage 1-4)
  Stage 6: 报告生成 (产出非程序员可读的业务全景报告)
"""

import os
import re
import json
import traceback
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
from loguru import logger
from core.shared_filter import SharedFilter
from core.gitnexus_client import GitNexusEnrichment
from core.code_knowledge_base import CodeKnowledgeBase, LLMAnalyzer as KbLLMAnalyzer
from core.prompt_extractor import PromptExtractor, PromptExtractionResult
from core.prompt_analyzer import PromptAnalyzer, PromptAnalysisResult


# ========================================================================
#  数据模型
# ========================================================================

@dataclass
class BusinessEntity:
    """业务实体 —— 代码中映射到业务概念的类/模块"""
    name: str                         # 业务名称 (如 "调研工具", "方案工具")
    technical_name: str               # 代码中的技术名称
    purpose: str                      # 业务目的 (一句话)
    files: List[str] = field(default_factory=list)     # 涉及的文件 (相对路径)
    core_classes: List[str] = field(default_factory=list)  # 核心类名
    capabilities: List[str] = field(default_factory=list)   # 业务能力列表


@dataclass
class UserRole:
    """用户角色"""
    name: str                         # 角色名
    description: str                  # 角色描述
    access_level: str                 # 权限级别
    accessible_features: List[str] = field(default_factory=list)
    ui_mode: str = ""                 # GUI / Web / 通用


@dataclass
class BusinessWorkflow:
    """业务流程"""
    name: str
    owner: str                        # 所属实体
    steps: List[str] = field(default_factory=list)     # 步骤描述
    trigger: str = ""                 # 触发条件
    output: str = ""                  # 产出物
    roles_involved: List[str] = field(default_factory=list)


@dataclass
class WorkflowHierarchy:
    """工作流层级节点 —— 按层级组织的业务流程树"""
    name: str                              # 层级名称
    level: int = 0                         # 层级深度（0=主轴入口, 1=一级, 2=二级...）
    description: str = ""                  # 层级描述
    module: str = ""                       # 所属模块
    steps: List[str] = field(default_factory=list)     # 该层级的关键步骤
    trigger: str = ""                      # 触发条件
    output: str = ""                       # 产出物
    roles_involved: List[str] = field(default_factory=list)  # 涉及角色
    children: List['WorkflowHierarchy'] = field(default_factory=list)  # 子层级
    is_spine: bool = False                 # 是否为主轴节点


@dataclass
class CrossCuttingDifference:
    """跨切面差异 (Web vs GUI, A角色 vs B角色 等)"""
    dimension: str                    # 对比维度 ("UI平台" / "用户角色" / "工具模式")
    aspect: str                       # 对比方面
    side_a: str                       # 对比方A
    side_b: str                       # 对比方B
    difference: str                   # 差异描述
    impact: str = ""                  # 对业务的影响


@dataclass
class AnalysisEvaluation:
    """自评估结果"""
    passed: bool
    score: float                      # 0-1
    issues: List[str] = field(default_factory=list)
    suggestions: List[str] = field(default_factory=list)


@dataclass
class BusinessAnalysisResult:
    """业务分析全量结果"""
    project_name: str = ""
    
    # 技术概览 (来自 CodeAnalyzer)
    tech_summary: str = ""
    languages: Dict[str, int] = field(default_factory=dict)
    file_count: int = 0
    line_count: int = 0
    total_classes: int = 0
    total_functions: int = 0
    
    # 业务层发现
    entities: List[BusinessEntity] = field(default_factory=list)
    roles: List[UserRole] = field(default_factory=list)
    workflows: List[BusinessWorkflow] = field(default_factory=list)
    hierarchy: List[WorkflowHierarchy] = field(default_factory=list)  # 层级化工作流树
    differences: List[CrossCuttingDifference] = field(default_factory=list)
    
    # GitNexus 增强数据
    enrichment: Optional[GitNexusEnrichment] = None

    # 自学习轨迹
    iteration_count: int = 1
    improvement_history: List[str] = field(default_factory=list)
    evaluation_scores: List[float] = field(default_factory=list)


# ========================================================================
#  业务分析引擎
# ========================================================================

class BusinessAnalyzer:
    """
    通用业务分析引擎
    
    用法:
        from core.business_analyzer import BusinessAnalyzer
        analyzer = BusinessAnalyzer(llm_client)
        result = analyzer.analyze(project_analysis)
        print(result.to_business_report())
    """
    
    # 自评估的检查项
    EVALUATION_CRITERIA = [
        "是否描述了项目或系统在做什么",
        "是否识别出了不同的用户角色",
        "是否描述了核心业务流程",
        "是否包含跨平台/跨端差异",
        "语言是否通俗易懂，非程序员能理解",
        "是否有业务实体之间的关系描述",
    ]
    
    def __init__(self, llm_client=None, gitnexus_client=None, knowledge_base=None):
        self.llm = llm_client         # LLMIntegration 实例 (可选)
        self.gitnexus = gitnexus_client  # GitNexusMCPClient 实例 (可选)
        self.kb = knowledge_base      # CodeKnowledgeBase 实例 (可选，LLM 驱动分析的核心)
        self._kb_analyzer = None      # LLMAnalyzer 实例 (延迟初始化)
        self._learning_history = []    # 自学习历史
        self._prompt_memory = ""       # 自学习中累积的「硬编码 Prompt」
        self._prompt_analysis = None   # PromptAnalysisResult（缓存，避免重复分析）

    def _get_kb_analyzer(self):
        """延迟初始化知识库分析器"""
        if self._kb_analyzer is None and self.kb is not None:
            self._kb_analyzer = KbLLMAnalyzer(self.kb, llm_client=self.llm)
        return self._kb_analyzer

    def _gitnexus_enrich(self, project_path: str) -> Optional['GitNexusEnrichment']:
        """Stage 0: GitNexus 增强 — 自动获取符号索引 + 调用图"""
        try:
            from core.gitnexus_client import GitNexusMCPClient
            if not GitNexusMCPClient.is_cli_available():
                logger.info("[BusinessAnalyzer] GitNexus CLI 不可用，跳过增强")
                return None
            with GitNexusMCPClient(project_path=project_path) as client:
                enrichment = client.enrich_project(project_path)
                if enrichment.available:
                    logger.info(f"[BusinessAnalyzer] GitNexus 增强可用: "
                               f"{len(enrichment.all_symbols)} 符号, "
                               f"{len(enrichment.call_pairs)} 调用关系, "
                               f"{len(enrichment.entry_points)} 入口点")
                return enrichment if enrichment.available else None
        except Exception as e:
            logger.warning(f"[BusinessAnalyzer] GitNexus 增强失败(跳过): {e}")
            return None

    def _prompt_enrich(self, project_path: str) -> Optional[PromptAnalysisResult]:
        """
        Stage 0.5: Prompt 抽取 + 角色分析
        
        从代码中的 Prompt 模板提取角色定义和工作流信息。
        这是连接"代码结构分析"和"业务语义理解"的关键桥梁。
        
        核心思路：
        - Prompt 是 Agent 的 DNA——system prompt 定义了角色行为
        - 通过抽取和分析 prompt，可以：
          1. 识别业务流程中的角色（如小验→小张→老商→小调）
          2. 提取角色使用的方法论/框架
          3. 重建端到端的工作流
        """
        try:
            # Step 1: 抽取 Prompt 模板
            extractor = PromptExtractor()
            prompt_result = extractor.extract_from_project(project_path)
            
            if prompt_result.total_prompts_found == 0:
                logger.info("[BusinessAnalyzer] 未发现 Prompt 模板，跳过 Prompt 增强")
                return None
            
            logger.info(f"[BusinessAnalyzer] Prompt 抽取完成: {prompt_result.total_prompts_found} 个 Prompt, "
                       f"角色模式: {prompt_result.role_patterns}")
            
            # Step 2: 分析 Prompt（提取角色 + 工作流）
            analyzer = PromptAnalyzer(llm_client=self.llm)
            analysis = analyzer.analyze(prompt_result)
            
            logger.info(f"[BusinessAnalyzer] Prompt 分析完成: {analysis.total_roles} 角色, "
                       f"{analysis.total_workflows} 工作流")
            
            return analysis
        except Exception as e:
            logger.warning(f"[BusinessAnalyzer] Prompt 增强失败(跳过): {e}")
            return None

    def analyze(self, project_analysis, max_iterations=3) -> BusinessAnalysisResult:
        """
        全量业务分析入口
        
        Args:
            project_analysis: ProjectAnalysis 对象 (来自 CodeAnalyzer)
            max_iterations: 最多自学习迭代次数
            
        Returns:
            BusinessAnalysisResult
        """
        # 加载项目专属的 cache 硬编码优化（白名单）
        SharedFilter.load_cache(project_analysis.project_path)

        result = BusinessAnalysisResult()
        proj_name = os.path.basename(project_analysis.project_path.rstrip('/\\').rstrip('\\'))
        result.project_name = proj_name
        result.file_count = project_analysis.total_files
        result.line_count = project_analysis.total_lines
        result.languages = dict(project_analysis.languages)
        result.tech_summary = project_analysis.architecture_summary
        result.total_classes = sum(len(f.classes) for f in project_analysis.files)
        result.total_functions = sum(len(f.functions) for f in project_analysis.files)
        
        # Stage 0: GitNexus 增强
        enrichment = self._gitnexus_enrich(project_analysis.project_path)
        result.enrichment = enrichment
        
        # Stage 0.5: Prompt 抽取 + 角色分析（核心创新：从 Prompt 中提取角色和流程）
        self._prompt_analysis = self._prompt_enrich(project_analysis.project_path)
        
        iteration = 0
        best_result = None
        best_score = 0.0
        
        while iteration < max_iterations:
            iteration += 1
            result.iteration_count = iteration
            logger.info(f"[BusinessAnalyzer] 第 {iteration} 轮分析开始")
            
            # --- Stage 1: 业务概念发现 ---
            entities = self._discover_business_entities(project_analysis, enrichment=enrichment)
            
            # --- Stage 2: 角色与工作流发现（传入累积学习记忆）---
            roles = self._discover_roles(project_analysis, entities)
            workflows = self._discover_workflows(project_analysis, entities, roles, enrichment=enrichment)
            
            # --- Stage 2.5: 层级化组织（找到主轴，按层级捋清楚）---
            hierarchy = self._organize_workflows_hierarchically(workflows, entities, roles, enrichment=enrichment)
            
            # --- Stage 3: 跨端与角色差异分析 ---
            differences = self._discover_cross_cutting_differences(
                project_analysis, entities, roles, enrichment=enrichment
            )
            
            # 更新结果
            result.entities = entities or []
            result.roles = roles or []
            result.workflows = workflows or []
            result.hierarchy = hierarchy or []
            result.differences = differences or []
            
            # --- Stage 4: 自评估 ---
            evaluation = self._evaluate_quality(result)
            result.evaluation_scores.append(evaluation.score)
            
            logger.info(f"[BusinessAnalyzer] 第 {iteration} 轮评估得分: {evaluation.score:.2f}")
            
            if evaluation.score > best_score:
                best_score = evaluation.score
                best_result = BusinessAnalysisResult(
                    project_name=result.project_name,
                    tech_summary=result.tech_summary,
                    languages=dict(result.languages),
                    file_count=result.file_count,
                    line_count=result.line_count,
                    total_classes=result.total_classes,
                    total_functions=result.total_functions,
                    entities=[BusinessEntity(**e.__dict__) for e in result.entities],
                    roles=[UserRole(**r.__dict__) for r in result.roles],
                    workflows=[BusinessWorkflow(**w.__dict__) for w in result.workflows],
                    hierarchy=[WorkflowHierarchy(
                        name=h.name, level=h.level, description=h.description,
                        module=h.module, steps=list(h.steps), trigger=h.trigger,
                        output=h.output, roles_involved=list(h.roles_involved),
                        children=list(h.children), is_spine=h.is_spine,
                    ) for h in result.hierarchy],
                    differences=[CrossCuttingDifference(**d.__dict__) for d in result.differences],
                    enrichment=result.enrichment,
                    iteration_count=iteration,
                    improvement_history=list(result.improvement_history),
                    evaluation_scores=list(result.evaluation_scores),
                )
            
            # 检查是否通过
            if evaluation.passed:
                logger.info(f"[BusinessAnalyzer] 第 {iteration} 轮通过评估，结束")
                break
            
            # --- Stage 5: 自改进（核心：LLM先分析、再硬编码更好的Prompt）---
            if iteration < max_iterations:
                self._prompt_memory = self._generate_improvement(result, evaluation)
                result.improvement_history.append(self._prompt_memory)
                self._learning_history.append({
                    "iteration": iteration,
                    "score": evaluation.score,
                    "improvement": self._prompt_memory,
                    "issues": evaluation.issues,
                })
                logger.info(f"[BusinessAnalyzer] 自改进: 已生成第{iteration+1}轮用的硬编码Prompt "
                          f"(len={len(self._prompt_memory)} chars)")
        
        # 返回最优结果
        if best_result:
            best_result.iteration_count = iteration
            best_result.improvement_history = result.improvement_history
            best_result.evaluation_scores = result.evaluation_scores
            return best_result
        
        return result
    
    # ====================================================================
    #  Stage 1: 业务概念发现
    # ====================================================================
    
    def _discover_business_entities(self, analysis, enrichment=None) -> List[BusinessEntity]:
        """从代码结构中发现业务实体（工具/模块/子系统）"""
        # 先尝试用无 LLM 的方式推断（保证即使无 LLM 也能给基本输出）
        entities = self._heuristic_entity_discovery(analysis)
        
        # GitNexus 增强：为实体补充符号级信息
        if enrichment and enrichment.available:
            entities = self._enrich_entities_with_symbols(entities, enrichment, analysis)
        
        # 如果有 LLM，再用 LLM 深度增强
        if self.llm and hasattr(self.llm, 'chat_completion'):
            llm_entities = self._llm_entity_discovery(analysis, enrichment=enrichment)
            if llm_entities:
                # 合并：以 LLM 发现为主
                entities = self._merge_entities(entities, llm_entities)
        
        return entities

    def _enrich_entities_with_symbols(self, entities, enrichment, analysis) -> List[BusinessEntity]:
        """用 GitNexus 符号数据增强实体（补充核心类/函数）"""
        for entity in entities:
            # 找该实体文件对应的 GitNexus 符号
            symbols_for_entity = []
            for f_rel in entity.files:
                abs_path = os.path.join(analysis.project_path, f_rel)
                norm = abs_path.replace('\\', '/')
                # 直接匹配
                if norm in enrichment.file_symbols:
                    symbols_for_entity.extend(enrichment.file_symbols[norm])
                # 尝试匹配后缀
                for fp, syms in enrichment.file_symbols.items():
                    if norm.endswith(fp) or fp.endswith(norm):
                        symbols_for_entity.extend(syms)

            if symbols_for_entity:
                # 提取函数名/类名
                func_names = [s.get("name", "") for s in symbols_for_entity
                             if s.get("type", "").lower() in ("function", "method", "")]
                class_names_from_gn = [s.get("name", "") for s in symbols_for_entity
                                       if s.get("type", "").lower() == "class"]
                # 补充到 entity 的 core_classes
                existing = set(entity.core_classes)
                for cn in class_names_from_gn:
                    if cn and cn not in existing:
                        entity.core_classes.append(cn)
                        existing.add(cn)
                # 如果没能力描述，用函数名推断
                if not entity.capabilities and func_names:
                    entity.capabilities = self._infer_capabilities_from_names(func_names)[:6]

        return entities
    
    def _heuristic_entity_discovery(self, analysis) -> List[BusinessEntity]:
        """
        基于代码结构的实体发现（LLM + 知识库驱动，无硬编码映射）
        
        核心改进：
        - 不再使用硬编码的目录名→业务名映射表
        - 不再使用硬编码的关键词→能力映射表
        - 通过知识库检索获取实际代码内容，而非仅文件名
        - LLM 看到代码内容后做出准确判断
        """
        entities = []
        
        # 通过顶层目录分组
        top_dirs = defaultdict(lambda: {"files": [], "classes": [], "funcs": [], "code_samples": []})
        for f in analysis.files:
            rel = os.path.relpath(f.file_path, analysis.project_path)
            parts = rel.replace('\\', '/').split('/')
            top = parts[0] if len(parts) >= 2 else "root"
            top_dirs[top]["files"].append(f.file_path)
            for cls in f.classes:
                if not cls.name.startswith('_'):
                    top_dirs[top]["classes"].append(cls.name)
            for func in f.functions:
                if not func.name.startswith('_'):
                    top_dirs[top]["funcs"].append(func.name)
            # 收集代码样本（docstring + 前几行代码）
            code_sample = self._extract_code_sample(f)
            if code_sample:
                top_dirs[top]["code_samples"].append(code_sample)
        
        # 为每个目录生成业务实体
        for dir_name, data in sorted(top_dirs.items(), key=lambda x: -len(x[1]["files"])):
            if dir_name in ('__pycache__', '.git', 'node_modules', 'venv', '.venv', 'data'):
                continue
            
            # 构建代码上下文（用于 LLM 推断）
            code_context = "\n".join(data["code_samples"][:5])  # 最多5个文件的代码样本
            
            # 从类名/函数名推断业务能力（LLM 驱动）
            class_signals = self._infer_capabilities_from_names(
                data["classes"], code_context=code_context
            )
            func_signals = self._infer_capabilities_from_names(
                data["funcs"], code_context=code_context
            )
            
            purpose_signals = class_signals + func_signals
            
            # 生成业务名称（LLM 驱动）
            business_name = self._dir_to_business_name(dir_name, code_context=code_context)
            
            # 生成业务目的（LLM 驱动）
            purpose = self._summarize_signals(purpose_signals, dir_name, code_context=code_context)
            
            # 真实文件数量（不截断）
            all_files = [os.path.relpath(f, analysis.project_path) for f in data["files"]]
            
            entity = BusinessEntity(
                name=business_name,
                technical_name=dir_name,
                purpose=purpose,
                files=all_files,  # 完整文件列表，不再截断为10
                core_classes=data["classes"][:12],
                capabilities=purpose_signals[:8],
            )
            entities.append(entity)
        
        # Prompt 增强：用 Prompt 角色信息丰富实体描述
        if self._prompt_analysis and self._prompt_analysis.roles:
            entities = self._enrich_entities_with_prompt_roles(entities, self._prompt_analysis)
        
        return entities

    def _extract_code_sample(self, cf) -> str:
        """从 CodeFile 提取代码样本（docstring + 类/函数签名）"""
        parts = []
        rel = os.path.relpath(cf.file_path, cf.file_path)  # placeholder
        parts.append(f"// {os.path.basename(cf.file_path)}")
        
        for cls in cf.classes[:3]:
            if cls.docstring:
                parts.append(f"class {cls.name}: {cls.docstring[:200]}")
            else:
                parts.append(f"class {cls.name}")
        
        for func in cf.functions[:3]:
            if func.docstring:
                parts.append(f"def {func.name}(): {func.docstring[:200]}")
            else:
                parts.append(f"def {func.name}()")
        
        return "\n".join(parts)

    def _enrich_entities_with_prompt_roles(
        self, entities: List[BusinessEntity], pa: PromptAnalysisResult
    ) -> List[BusinessEntity]:
        """
        用 Prompt 角色信息丰富实体描述
        
        核心逻辑：如果一个模块的 Prompt 中定义了角色，用角色的职责描述
        来增强这个模块的 business purpose。这比仅从类名推断准确得多。
        """
        # 构建模块→角色列表的映射
        module_roles: Dict[str, List[str]] = {}
        for r in pa.roles:
            module = r.source_module if r.source_module != 'root' else '其他'
            if module not in module_roles:
                module_roles[module] = []
            role_info = r.name
            if r.responsibility:
                role_info += f"({r.responsibility[:30]})"
            if r.nickname:
                role_info = f"{r.nickname}({r.name})"
            module_roles[module].append(role_info)
        
        # 为每个实体查找对应的 Prompt 角色
        for entity in entities:
            tech_name = entity.technical_name.lower()
            
            # 尝试匹配模块名
            matched_roles = []
            for module, roles in module_roles.items():
                if module.lower() in tech_name or tech_name in module.lower():
                    matched_roles.extend(roles)
            
            if matched_roles:
                # 用角色信息增强目的描述
                if "LLM调用错误" in entity.purpose or not entity.purpose or len(entity.purpose) < 20:
                    entity.purpose = f"本模块包含以下 AI Agent 角色：{'、'.join(matched_roles[:8])}"
                
                # 用角色信息增强能力列表
                role_based_caps = [f"AI角色: {r}" for r in matched_roles[:6]]
                # 合并（角色信息优先）
                entity.capabilities = role_based_caps + [c for c in entity.capabilities if not c.startswith('AI角色')]
                entity.capabilities = entity.capabilities[:8]
        
        return entities
    
    def _dir_to_business_name(self, dir_name: str, code_context: str = "") -> str:
        """
        将目录名转换为业务名称（LLM 驱动，无硬编码映射）
        
        当 LLM 不可用时，使用基本的文本清理作为降级方案。
        """
        # 如果有 LLM 且提供了代码上下文，用 LLM 推断
        if self.llm and hasattr(self.llm, 'chat_completion') and code_context:
            try:
                prompt = f"""根据以下代码目录的内容，推断这个目录在业务上应该叫什么名字（通俗中文，2-6个字）：
                
目录名: {dir_name}
代码内容摘要:
{code_context[:2000]}

请仅返回业务名称，不要其他内容。例如："调研工具"、"配置中心"、"创意引擎"."""
                result = self.llm.chat_completion([
                    {"role": "system", "content": "你是一个业务命名专家。请仅返回简洁的业务名称。"},
                    {"role": "user", "content": prompt}
                ])
                name = result.strip().strip('"').strip("'")
                if 2 <= len(name) <= 20:
                    return name
            except Exception:
                pass
        
        # 降级：基本文本清理（不依赖任何硬编码映射表）
        clean = re.sub(r'[-_]', ' ', dir_name)
        return clean.strip()
    
    def _infer_capabilities_from_names(self, names: List[str], code_context: str = "") -> List[str]:
        """
        从类名/函数名推断业务能力（LLM 驱动，无硬编码关键词映射）
        
        当 LLM 不可用时，使用类名/函数名本身作为能力标签。
        """
        if not names:
            return []
        
        # 如果有 LLM 且提供了代码上下文，用 LLM 推断
        if self.llm and hasattr(self.llm, 'chat_completion') and code_context:
            try:
                names_list = ", ".join(names[:20])
                prompt = f"""根据以下代码中的类名/函数名和代码内容，推断这个模块的业务能力（用通俗中文描述，3-8个字每条）：
                
类名/函数名: {names_list}
代码内容摘要:
{code_context[:2000]}

请仅返回 JSON 数组格式，如 ["能力1", "能力2", "能力3"]，最多6条。"""
                result = self.llm.chat_completion([
                    {"role": "system", "content": "你是一个代码分析专家。请仅返回JSON数组格式的能力列表。"},
                    {"role": "user", "content": prompt}
                ])
                # 提取 JSON 数组
                json_match = re.search(r'\[.*\]', result, re.DOTALL)
                if json_match:
                    caps = json.loads(json_match.group())
                    if isinstance(caps, list) and len(caps) > 0:
                        return caps[:8]
            except Exception:
                pass
        
        # 降级：使用类名/函数名本身作为能力标签（不依赖硬编码映射）
        # 清理名称：去掉下划线，限制长度
        cleaned = []
        seen = set()
        for name in names[:8]:
            clean = name.replace('_', ' ').strip()
            if len(clean) > 15:
                clean = clean[:15]
            if clean and clean not in seen:
                cleaned.append(clean)
                seen.add(clean)
        return cleaned
    
    def _summarize_signals(self, signals: List[str], dir_name: str, code_context: str = "") -> str:
        """
        综合信号生成一句话业务目的（LLM 驱动，无模板拼接）
        """
        if not signals:
            return f"提供 {dir_name} 相关功能"
        
        # 如果有 LLM 且提供了代码上下文，用 LLM 生成
        if self.llm and hasattr(self.llm, 'chat_completion') and code_context:
            try:
                signals_str = "、".join(signals[:8])
                prompt = f"""根据以下信息，用一句话（20-40字）描述这个模块的业务目的：
                
模块目录: {dir_name}
代码信号: {signals_str}
代码内容摘要:
{code_context[:1500]}

请仅返回一句话描述，不要其他内容。"""
                result = self.llm.chat_completion([
                    {"role": "system", "content": "你是一个业务分析专家。请用一句话描述模块的业务目的。"},
                    {"role": "user", "content": prompt}
                ])
                desc = result.strip().strip('"').strip("'")
                if 10 <= len(desc) <= 100:
                    return desc
            except Exception:
                pass
        
        # 降级：简单拼接（不依赖硬编码模板）
        unique = list(dict.fromkeys(signals))
        if len(unique) <= 3:
            return "、".join(unique)
        return "、".join(unique[:3]) + " 等功能"
    
    def _llm_entity_discovery(self, analysis, enrichment=None) -> List[BusinessEntity]:
        """用 LLM 深入发现业务实体"""
        # 准备紧凑的代码概览
        project_name = os.path.basename(analysis.project_path.rstrip('/\\').rstrip('\\'))
        overview = self._build_compact_overview(analysis)

        # GitNexus 增强数据
        gn_section = ""
        if enrichment and enrichment.available and enrichment.entry_points:
            gn_section = (
                f"\n【GitNexus 代码索引发现的入口点】\n"
                f"以下函数是代码库中被调用最多的核心入口：\n"
            )
            for ep in enrichment.entry_points[:10]:
                gn_section += f"- {ep}\n"
            if enrichment.callee_index:
                gn_section += "\n【关键调用链】\n"
                count = 0
                for caller, callees in enrichment.callee_index.items():
                    if count >= 10:
                        break
                    gn_section += f"- {caller} -> {', '.join(callees[:4])}\n"
                    count += 1

        # 自学习经验注入
        learning_section = ""
        if self._prompt_memory:
            learning_section = (
                f"\n【上一轮分析的经验与改进方向】\n"
                f"{self._prompt_memory[:1500]}\n"
                f"请特别关注上述改进方向，并以此为指导进行更深入的分析。\n"
            )

        prompt = f"""你是一位资深的**业务架构师**。请阅读下面的代码项目概览，找出该项目中所有**业务实体**（业务模块 / 子系统 / 业务工具）。

【输出要求】
- 每个业务实体 = 一个在业务上有明确边界的子系统
- 基于你看到的类名、函数名、文件结构来推断，不要编造
- 用**通俗的业务语言**描述，不要说技术细节

【代码项目概览】
项目名称: {project_name}
文件数: {analysis.total_files}
代码行数: {analysis.total_lines:,}

{overview}
{gn_section}
{learning_section}

请以 JSON 格式返回，仅返回 JSON，不要其他文字：
{{
  "entities": [
    {{
      "name": "业务名称（通俗中文）",
      "technical_name": "代码中的模块/目录名",
      "purpose": "一句话说明这个模块在业务上做什么",
      "core_classes": ["类名1", "类名2"],
      "capabilities": ["能力描述1", "能力描述2"]
    }}
  ]
}}"""
        
        response = self._call_llm(prompt)
        entities = self._parse_llm_entities(response)
        
        if not entities:
            logger.warning("[BusinessAnalyzer] LLM 未返回有效的业务实体，使用启发式结果")
        
        return entities
    
    def _build_compact_overview(self, analysis) -> str:
        """
        构建紧凑的代码概览，用于 LLM 分析
        
        核心改进：不仅提供文件名和类名，还提供 docstring 和代码片段，
        让 LLM 能真正理解代码的业务含义。
        """
        lines = []
        
        # 按顶层目录组织
        dir_groups = defaultdict(list)
        for f in analysis.files:
            rel = os.path.relpath(f.file_path, analysis.project_path)
            parts = rel.replace('\\', '/').split('/')
            top = parts[0] if len(parts) >= 2 else "."
            dir_groups[top].append(f)
        
        for dir_name, files in sorted(dir_groups.items()):
            if dir_name in ('__pycache__', '.git', 'node_modules'):
                continue
            lines.append(f"\n## 目录: {dir_name}")
            for f in files[:8]:  # 每个目录只看前 8 个文件
                rel = os.path.relpath(f.file_path, analysis.project_path)
                class_names = [c.name for c in f.classes[:3] if not c.name.startswith('_')]
                func_names = [fn.name for fn in f.functions[:4] if not fn.name.startswith('_')]
                
                # 收集 docstring（关键改进：给 LLM 提供实际业务描述）
                doc_hints = []
                for c in f.classes:
                    if c.docstring and len(c.docstring) > 10:
                        doc_hints.append(f"[{c.name}] {c.docstring[:150].strip()}")
                for fn in f.functions:
                    if fn.docstring and len(fn.docstring) > 10:
                        doc_hints.append(f"[{fn.name}()] {fn.docstring[:150].strip()}")
                
                parts_out = []
                if class_names:
                    parts_out.append(f"类: {', '.join(class_names)}")
                if func_names:
                    parts_out.append(f"函数: {', '.join(func_names)}")
                detail = " | ".join(parts_out) if parts_out else ""
                lines.append(f"  📄 {rel} {detail}")
                
                # 输出 docstring（关键改进）
                for hint in doc_hints[:3]:
                    lines.append(f"    💬 {hint}")
            
            if len(files) > 8:
                lines.append(f"  ... 及另外 {len(files) - 8} 个文件")
        
        return "\n".join(lines)
    
    def _parse_llm_entities(self, response: str) -> List[BusinessEntity]:
        """解析 LLM 返回的业务实体 JSON"""
        try:
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if not json_match:
                return []
            data = json.loads(json_match.group())
            entities_data = data.get("entities", [])
            return [
                BusinessEntity(
                    name=e.get("name", "未知"),
                    technical_name=e.get("technical_name", ""),
                    purpose=e.get("purpose", ""),
                    core_classes=e.get("core_classes", []),
                    capabilities=e.get("capabilities", []),
                )
                for e in entities_data
            ]
        except Exception as ex:
            logger.warning(f"[BusinessAnalyzer] 解析LLM实体失败: {ex}")
            return []
    
    def _merge_entities(self, heuristic: List[BusinessEntity], llm: List[BusinessEntity]) -> List[BusinessEntity]:
        """合并启发式和 LLM 发现的实体，以 LLM 为主"""
        if not llm:
            return heuristic
        
        # 用LLM结果，但补充启发式中独特的文件信息
        llm_names = {e.technical_name for e in llm}
        merged = list(llm)
        
        for h in heuristic:
            if h.technical_name not in llm_names:
                merged.append(h)
        
        return merged
    
    # ====================================================================
    #  Stage 2: 角色与工作流发现
    # ====================================================================
    
    def _discover_roles(self, analysis, entities: List[BusinessEntity]) -> List[UserRole]:
        """发现用户角色"""
        # 优先使用 Prompt 分析中提取的角色
        if self._prompt_analysis and self._prompt_analysis.roles:
            roles = self._roles_from_prompt_analysis(self._prompt_analysis)
            if roles:
                logger.info(f"[BusinessAnalyzer] 从 Prompt 中提取到 {len(roles)} 个角色")
                return roles
        
        if self.llm and hasattr(self.llm, 'chat_completion'):
            return self._llm_role_discovery(analysis, entities)
        return self._heuristic_role_discovery(analysis)

    def _roles_from_prompt_analysis(self, pa: PromptAnalysisResult) -> List[UserRole]:
        """将 Prompt 分析结果中的角色转换为 UserRole 列表"""
        roles = []
        for r in pa.roles:
            # 构建描述
            description_parts = []
            if r.responsibility:
                description_parts.append(r.responsibility)
            if r.methods:
                description_parts.append(f"方法论：{'; '.join(r.methods[:3])}")
            if r.upstream_roles:
                description_parts.append(f"上游：{', '.join(r.upstream_roles)}")
            if r.downstream_roles:
                description_parts.append(f"下游：{', '.join(r.downstream_roles)}")
            
            # 判断角色类型
            if r.nickname:
                # 昵称化角色 → 业务流程内的 Agent 角色
                access_level = "Agent角色"
                ui_mode = "LLM Agent (有昵称)"
            elif r.responsibility:
                access_level = "分析角色"
                ui_mode = "LLM Agent (有职责)"
            else:
                access_level = "职能角色"
                ui_mode = "LLM Agent"
            
            roles.append(UserRole(
                name=r.name,
                description="; ".join(description_parts) if description_parts else r.description,
                access_level=access_level,
                ui_mode=ui_mode,
            ))
        
        return roles
    
    def _heuristic_role_discovery(self, analysis) -> List[UserRole]:
        """
        发现用户角色（LLM 驱动，无硬编码 admin/user 假设）
        """
        roles = []
        
        # 如果有 LLM，用 LLM 分析
        if self.llm and hasattr(self.llm, 'chat_completion'):
            # 扫描代码中角色相关的线索
            role_clues = []
            for f in analysis.files:
                content = getattr(f, 'raw_content', '') or ''
                # 查找角色相关的代码模式
                for keyword in ['role', '角色', 'admin', 'permission', 'user_type', 'access_level', 'A角色', 'B角色']:
                    if keyword in content:
                        # 提取包含关键词的行
                        for line in content.split('\n')[:500]:
                            if keyword in line:
                                role_clues.append(line.strip()[:150])
                                if len(role_clues) >= 20:
                                    break
                    if len(role_clues) >= 20:
                        break
                if len(role_clues) >= 20:
                    break
            
            if role_clues:
                try:
                    clues_text = "\n".join(role_clues[:15])
                    prompt = f"""分析以下代码中的用户角色线索，推断系统有哪些用户角色：
                    
{clues_text}

返回 JSON 格式：
[{{"name": "角色名", "description": "角色描述", "access_level": "高/中/低", "ui_mode": "Web/GUI/通用"}}]

如果没有明确的角色设计，返回空数组 []。"""
                    result = self.llm.chat_completion([
                        {"role": "system", "content": "你是一个用户角色分析专家。请返回JSON格式。"},
                        {"role": "user", "content": prompt}
                    ])
                    json_match = re.search(r'\[.*\]', result, re.DOTALL)
                    if json_match:
                        role_data = json.loads(json_match.group())
                        for r in role_data:
                            roles.append(UserRole(
                                name=r.get("name", "未知"),
                                description=r.get("description", ""),
                                access_level=r.get("access_level", "标准"),
                                ui_mode=r.get("ui_mode", ""),
                            ))
                        if roles:
                            return roles
                except Exception:
                    pass
        
        # 降级：不做任何假设，返回空（不硬编码 admin/user）
        return roles
    
    def _llm_role_discovery(self, analysis, entities: List[BusinessEntity]) -> List[UserRole]:
        """用 LLM 发现用户角色"""
        entity_desc = "\n".join(
            f"- {e.name} ({e.technical_name}): {e.purpose}"
            for e in entities[:8]
        )
        
        # 查看是否有配置文件包含角色信息
        config_hint = self._find_role_config(analysis)
        
        learning_section = ""
        if self._prompt_memory:
            learning_section = f"\n【上一轮分析的经验】\n{self._prompt_memory[:1000]}\n请在角色分析中重点关注上述方向。\n"
        
        prompt = f"""你是一位**业务分析师**。请分析以下项目的业务实体，推断出这个系统有哪些**用户角色**。

【项目业务实体】
{entity_desc}

{config_hint}
{learning_section}

【分析要求】
1. 从业务实体的用途推断谁会使用它
2. 如果代码中出现了 "A角色/B角色"、"管理员/普通用户" 等概念，提取出来
3. 区分不同角色的权限差异
4. 用通俗的业务语言描述

请以 JSON 格式返回，仅返回 JSON：
{{
  "roles": [
    {{
      "name": "角色名（通俗中文）",
      "description": "这个角色是谁，在系统中做什么",
      "access_level": "高/中/低",
      "accessible_features": ["可以使用的功能1", "功能2"],
      "ui_mode": "Web / GUI / 通用"
    }}
  ]
}}"""
        
        response = self._call_llm(prompt)
        return self._parse_llm_roles(response)
    
    def _find_role_config(self, analysis) -> str:
        """查找配置中的角色信息"""
        hints = []
        for f in analysis.files:
            content = getattr(f, 'raw_content', '') or ''
            if 'is_admin' in content or 'admin' in f.file_path.lower():
                hints.append(f"文件 {os.path.relpath(f.file_path, analysis.project_path)} 包含 'admin' 相关配置")
            if 'role' in content.lower() and 'permission' in content.lower():
                hints.append(f"文件 {os.path.relpath(f.file_path, analysis.project_path)} 包含角色权限定义")
        
        if hints:
            return "【在代码中发现的角色线索】\n" + "\n".join(hints[:5])
        return ""
    
    def _parse_llm_roles(self, response: str) -> List[UserRole]:
        """解析 LLM 返回的角色 JSON"""
        try:
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if not json_match:
                return []
            data = json.loads(json_match.group())
            return [
                UserRole(
                    name=r.get("name", "未知角色"),
                    description=r.get("description", ""),
                    access_level=r.get("access_level", "标准"),
                    accessible_features=r.get("accessible_features", []),
                    ui_mode=r.get("ui_mode", ""),
                )
                for r in data.get("roles", [])
            ]
        except Exception as ex:
            logger.warning(f"[BusinessAnalyzer] 解析LLM角色失败: {ex}")
            return []
    
    def _discover_workflows(self, analysis, entities: List[BusinessEntity],
                            roles: List[UserRole], enrichment=None) -> List[BusinessWorkflow]:
        """发现业务流程"""
        # 优先使用 Prompt 分析中提取的工作流
        if self._prompt_analysis and self._prompt_analysis.workflows:
            workflows = self._workflows_from_prompt_analysis(self._prompt_analysis)
            if workflows:
                logger.info(f"[BusinessAnalyzer] 从 Prompt 中提取到 {len(workflows)} 个工作流")
                return workflows
    
    def _organize_workflows_hierarchically(
        self, workflows: List[BusinessWorkflow], entities: List[BusinessEntity],
        roles: List[UserRole], enrichment=None
    ) -> List[WorkflowHierarchy]:
        """
        找到主轴，按层级捋清楚业务流程
        
        核心策略（模拟 AI 直读代码的做法）：
        1. 优先使用 GitNexus 调用链重建模块级调度关系（真实代码证据）
        2. 其次用 LLM 推断层级关系（语义理解）
        3. 最后用规则降级（启发式）
        
        调用链是"骨架"，LLM 分析是"血肉"——结合两者才最准确。
        """
        if not workflows:
            return []
        
        # ── 优先级 1：GitNexus 调用链（真实代码证据）──
        if enrichment and enrichment.call_pairs:
            try:
                call_hierarchy = self._build_hierarchy_from_callgraph(
                    enrichment, entities, workflows, roles
                )
                if call_hierarchy:
                    logger.info(f"[BusinessAnalyzer] 从 GitNexus 调用链重建层级: {len(call_hierarchy)} 个主轴节点, "
                               f"共 {sum(1 + len(h.children) for h in call_hierarchy)} 个节点")
                    return call_hierarchy
            except Exception as e:
                logger.warning(f"[BusinessAnalyzer] GitNexus 调用链层级化失败，回退: {e}")
        
        # ── 优先级 2：LLM 推断层级 ──
        if self.llm and hasattr(self.llm, 'chat_completion'):
            try:
                return self._llm_hierarchical_workflows(workflows, entities, roles)
            except Exception as e:
                logger.warning(f"[BusinessAnalyzer] LLM 层级化失败，使用规则降级: {e}")
        
        # ── 优先级 3：规则推断 ──
        return self._rule_hierarchical_workflows(workflows, entities, roles)
    
    def _build_hierarchy_from_callgraph(
        self, enrichment, entities: List[BusinessEntity],
        workflows: List[BusinessWorkflow], roles: List[UserRole]
    ) -> List[WorkflowHierarchy]:
        """
        从 GitNexus 调用链重建模块级层级关系（V7：正确利用 caller_index 反向追溯）
        
        核心策略改变：
        - V6 问题：把 entry_points（被引用最多的符号）当主轴，结果 shared 成了主轴
        - V7 修复：利用 caller_index（callee→callers）反向追溯，结合出度/入度比
          正确识别入口层、业务层、基础设施层
        
        三层架构：
        - 入口层（出度 >> 入度）：web、gui —— 用户直接交互的界面
        - 业务层（调用 shared 的模块）：调研工具、洞察工具、方案工具等
        - 基础设施层（入度 >> 出度）：shared、配置中心 —— 被所有业务模块调用
        """
        # ── Step 1: 构建 func_name → module_name 映射 ──
        func_to_module = {}  # func_name → module_name
        func_to_file = {}    # func_name → file_path
        
        # 优先使用 file_symbols（更精确）
        for file_path, symbols in enrichment.file_symbols.items():
            module = self._extract_module_from_path(file_path)
            for s in symbols:
                name = s.get("name", "")
                if name:
                    func_to_module[name] = module
                    func_to_file[name] = file_path
        
        if not func_to_module and enrichment.all_symbols:
            for s in enrichment.all_symbols:
                name = s.get("name", "")
                fp = s.get("filePath", s.get("file_path", ""))
                if name and fp:
                    module = self._extract_module_from_path(fp)
                    func_to_module[name] = module
                    func_to_file[name] = fp
        
        if not func_to_module:
            logger.warning("[BusinessAnalyzer] 无法构建 func→module 映射，回退")
            return []
        
        # ── Step 2: 构建双向模块级调用图 ──
        # outgoing: module → {它调用的模块}
        # incoming: module → {调用它的模块}（利用 caller_index 反向追溯）
        module_outgoing = defaultdict(set)
        module_incoming = defaultdict(set)
        module_edge_count = defaultdict(lambda: defaultdict(int))
        
        # 2a: 从 call_pairs 直接构建 outgoing
        for caller, callee, rel_type in enrichment.call_pairs:
            caller_mod = func_to_module.get(caller)
            callee_mod = func_to_module.get(callee)
            if caller_mod and callee_mod and caller_mod != callee_mod:
                module_outgoing[caller_mod].add(callee_mod)
                module_incoming[callee_mod].add(caller_mod)
                module_edge_count[caller_mod][callee_mod] += 1
        
        # 2b: 利用 caller_index 补充 incoming（callee → [callers]）
        if enrichment.caller_index:
            for callee_name, caller_names in enrichment.caller_index.items():
                callee_mod = func_to_module.get(callee_name)
                if not callee_mod:
                    continue
                for caller_name in caller_names:
                    caller_mod = func_to_module.get(caller_name)
                    if caller_mod and caller_mod != callee_mod:
                        module_incoming[callee_mod].add(caller_mod)
                        module_outgoing[caller_mod].add(callee_mod)
                        module_edge_count[caller_mod][callee_mod] += 1
        
        # 2c: 利用 callee_index 补充 outgoing（caller → [callees]）
        if enrichment.callee_index:
            for caller_name, callee_names in enrichment.callee_index.items():
                caller_mod = func_to_module.get(caller_name)
                if not caller_mod:
                    continue
                for callee_name in callee_names:
                    callee_mod = func_to_module.get(callee_name)
                    if callee_mod and caller_mod != callee_mod:
                        module_outgoing[caller_mod].add(callee_mod)
                        module_incoming[callee_mod].add(caller_mod)
                        module_edge_count[caller_mod][callee_mod] += 1
        
        all_modules = set(list(module_outgoing.keys()) + list(module_incoming.keys()))
        
        # 过滤非模块名（单个 .py 文件、测试文件等）
        noise_patterns = {'.py', 'test_', '_test', 'install_', 'license_', 'setup'}
        filtered_modules = set()
        for m in all_modules:
            m_lower = m.lower()
            if m_lower.endswith('.py'):
                continue  # 单个文件，不是模块目录
            if any(p in m_lower for p in noise_patterns):
                continue  # 测试/安装/许可证脚本
            filtered_modules.add(m)
        
        all_modules = filtered_modules
        
        if not all_modules:
            logger.warning("[BusinessAnalyzer] 过滤后无模块，回退")
            return []
        
        # ── Step 3: 计算出度/入度，识别三层架构 ──
        out_degree = {m: len(module_outgoing.get(m, set())) for m in all_modules}
        in_degree = {m: len(module_incoming.get(m, set())) for m in all_modules}
        
        # 入口模块特征：出度 > 入度（调用别人多，被调用少）+ 路径包含 web/gui
        entry_keywords = {'web', 'gui', 'app', 'frontend', 'ui', 'client'}
        entry_modules = set()
        for m in all_modules:
            m_lower = m.lower()
            is_entry_path = any(kw in m_lower for kw in entry_keywords)
            # V7.1: 收紧阈值 1.5→2.0，避免业务模块（如洞察工具 8/5）被误判为入口
            is_entry_degree = out_degree.get(m, 0) > in_degree.get(m, 0) * 2.0
            if is_entry_path or is_entry_degree:
                entry_modules.add(m)
        
        # 基础设施模块特征：入度 >> 出度（被调用多，调用别人少）+ 路径包含 shared/common/core/config
        infra_keywords = {'shared', 'common', 'core', 'config', 'util', 'base', 'lib'}
        infra_modules = set()
        for m in all_modules:
            m_lower = m.lower()
            is_infra_path = any(kw in m_lower for kw in infra_keywords)
            is_infra_degree = in_degree.get(m, 0) > out_degree.get(m, 0) * 2 and in_degree.get(m, 0) >= 2
            if is_infra_path or is_infra_degree:
                infra_modules.add(m)
        
        # 业务模块：调用基础设施的模块 + 其他模块
        business_modules = set()
        for m in all_modules:
            if m in entry_modules or m in infra_modules:
                continue
            # 如果它调用了基础设施模块，或者被入口模块调用
            calls_infra = bool(module_outgoing.get(m, set()) & infra_modules)
            called_by_entry = bool(module_incoming.get(m, set()) & entry_modules)
            if calls_infra or called_by_entry:
                business_modules.add(m)
        
        # 收尾：把既不是入口也不是基础设施也不是业务的模块归入业务
        orphan_modules = all_modules - entry_modules - infra_modules - business_modules
        business_modules |= orphan_modules
        
        logger.info(f"[BusinessAnalyzer] V7 三层架构识别: "
                   f"入口={entry_modules}, 业务={business_modules}, 基础设施={infra_modules}")
        logger.info(f"[BusinessAnalyzer] 出度/入度: { {m: f'{out_degree.get(m,0)}/{in_degree.get(m,0)}' for m in all_modules} }")
        
        # ── Step 4: 确定主轴（入口模块中优先选 web，其次选出度最大的）──
        spine_module = None
        if entry_modules:
            # 优先选 web 相关入口（真正的用户交互入口）
            web_entry = [m for m in entry_modules if 'web' in m.lower()]
            if web_entry:
                spine_module = web_entry[0]
            else:
                spine_module = max(entry_modules, key=lambda m: out_degree.get(m, 0))
        if not spine_module and business_modules:
            # 退而求其次：选业务模块中出度最大的
            spine_module = max(business_modules, key=lambda m: out_degree.get(m, 0))
        if not spine_module and entities:
            spine_module = max(entities, key=lambda e: len(e.files)).technical_name
        
        if not spine_module:
            logger.warning("[BusinessAnalyzer] 无法确定主轴模块")
            return []
        
        logger.info(f"[BusinessAnalyzer] V7 调用链重建: 主轴={spine_module}, "
                   f"模块: {len(all_modules)} 个, "
                   f"边: {sum(len(v) for v in module_outgoing.values())} 条")
        
        # ── Step 5: 从主轴出发，构建三层层级树 ──
        # 层级结构：入口 → 业务 → 基础设施
        # 从主轴出发，先找它直接调用的模块（业务层），再找业务层调用的模块（基础设施层）
        
        hierarchy = []
        
        # 主轴节点
        spine_entity = next((e for e in entities if e.technical_name == spine_module), None)
        spine_node = WorkflowHierarchy(
            name=spine_entity.name if spine_entity else spine_module,
            level=0,
            description=spine_entity.purpose if spine_entity else f"用户交互入口，调度 {out_degree.get(spine_module, 0)} 个模块",
            module=spine_module,
            is_spine=True,
            trigger="用户请求",
            output="业务结果",
        )
        
        # 一级子节点：业务模块（被主轴调用 或 调用基础设施的模块）
        # 优先用真正被主轴调用的模块，其次用所有业务模块
        direct_callees = module_outgoing.get(spine_module, set())
        level1_modules = (direct_callees & business_modules) | business_modules
        
        # 排序：按调用次数降序
        sorted_level1 = sorted(
            level1_modules,
            key=lambda m: (
                module_edge_count.get(spine_module, {}).get(m, 0) +  # 主轴调用次数
                in_degree.get(m, 0) * 0.1  # 被调用次数作为次要排序
            ),
            reverse=True
        )
        
        for module_name in sorted_level1:
            entity = next((e for e in entities if e.technical_name == module_name), None)
            module_workflows = [w for w in workflows if w.owner == module_name]
            
            # 该模块调用的基础设施模块（二级）
            sub_callees = module_outgoing.get(module_name, set()) & infra_modules
            sub_callees -= {spine_module}  # 排除回环
            
            child = WorkflowHierarchy(
                name=entity.name if entity else module_name,
                level=1,
                description=entity.purpose if entity else f"{spine_module} 调度的业务模块",
                module=module_name,
                is_spine=False,
                trigger=f"用户通过 {spine_module} 触发",
                output=f"{module_name} 产出结果",
            )
            
            # 填充工作流步骤
            if module_workflows:
                wf = module_workflows[0]
                child.steps = wf.steps[:8]
                child.roles_involved = wf.roles_involved[:8]
            elif entity:
                child.steps = [f"执行 {entity.name} 相关操作"]
            
            # 二级子节点：该模块调用的基础设施模块
            for sub_module in sorted(sub_callees,
                                     key=lambda m: module_edge_count.get(module_name, {}).get(m, 0),
                                     reverse=True):
                sub_entity = next((e for e in entities if e.technical_name == sub_module), None)
                sub_workflows = [w for w in workflows if w.owner == sub_module]
                
                sub_child = WorkflowHierarchy(
                    name=sub_entity.name if sub_entity else sub_module,
                    level=2,
                    description=sub_entity.purpose[:120] if sub_entity else f"被 {module_name} 调用",
                    module=sub_module,
                    is_spine=False,
                )
                if sub_workflows:
                    sub_child.steps = sub_workflows[0].steps[:5]
                    sub_child.roles_involved = sub_workflows[0].roles_involved[:5]
                
                child.children.append(sub_child)
            
            spine_node.children.append(child)
        
        # 如果有未被归入层级的基础设施模块，作为独立节点挂在主轴下
        covered_modules = {spine_module} | level1_modules
        for child in spine_node.children:
            covered_modules.add(child.module)
            for sub in child.children:
                covered_modules.add(sub.module)
        
        uncovered_infra = infra_modules - covered_modules
        for mod in uncovered_infra:
            entity = next((e for e in entities if e.technical_name == mod), None)
            spine_node.children.append(WorkflowHierarchy(
                name=entity.name if entity else mod,
                level=1,
                description=entity.purpose if entity else "基础设施模块",
                module=mod,
                is_spine=False,
                steps=[f"为其他模块提供 {entity.name if entity else mod} 服务"],
            ))
        
        hierarchy.append(spine_node)
        
        # ── Step 6: 用 LLM 丰富描述（如果有 LLM）──
        if self.llm and hasattr(self.llm, 'chat_completion'):
            try:
                hierarchy = self._enrich_hierarchy_with_llm(
                    hierarchy, spine_module, module_edge_count
                )
            except Exception as e:
                logger.debug(f"[BusinessAnalyzer] LLM 丰富层级描述失败: {e}")
        
        return hierarchy
    
    def _extract_module_from_path(self, file_path: str) -> str:
        """从文件路径提取模块名（项目根目录下的第一层）"""
        # 标准化路径
        clean = file_path.replace('\\', '/')
        # 去掉可能的前缀
        for prefix in ['working/', 'project/', 'src/']:
            if clean.startswith(prefix):
                clean = clean[len(prefix):]
                break
        parts = clean.split('/')
        if len(parts) >= 1:
            mod = parts[0]
            # 过滤掉非模块的目录名
            skip = {'__pycache__', '.git', 'node_modules', 'venv', '.venv', 'data', 'tests', 'docs', '.'}
            if mod not in skip and mod:
                return mod
        return "root"
    
    def _enrich_hierarchy_with_llm(
        self, hierarchy: List[WorkflowHierarchy], spine_module: str,
        module_call_count: Dict[str, Dict[str, int]]
    ) -> List[WorkflowHierarchy]:
        """用 LLM 丰富层级节点的描述（不改变结构，只优化文字）"""
        # 收集需要丰富描述的节点
        nodes_to_enrich = []
        for h in hierarchy:
            if not h.description or len(h.description) < 20:
                nodes_to_enrich.append({
                    'name': h.name,
                    'module': h.module,
                    'level': h.level,
                    'called_modules': list(module_call_count.get(h.module, {}).keys())[:5],
                })
            for child in h.children:
                if not child.description or len(child.description) < 20:
                    nodes_to_enrich.append({
                        'name': child.name,
                        'module': child.module,
                        'level': child.level,
                        'called_modules': list(module_call_count.get(child.module, {}).keys())[:5],
                    })
        
        if not nodes_to_enrich:
            return hierarchy
        
        prompt = f"""根据以下模块调用关系，为每个模块生成一句话业务描述（20-40字）。

主轴模块: {spine_module}
模块列表:
{json.dumps(nodes_to_enrich, ensure_ascii=False, indent=2)}

返回 JSON 数组:
[{{"module": "模块名", "description": "一句话业务描述"}}]"""
        
        try:
            response = self.llm.chat_completion([
                {"role": "system", "content": "你是一个业务分析师。请仅返回JSON格式。"},
                {"role": "user", "content": prompt}
            ])
            json_match = re.search(r'\[.*\]', response, re.DOTALL)
            if json_match:
                enrichments = json.loads(json_match.group())
                enrich_map = {e['module']: e['description'] for e in enrichments}
                
                for h in hierarchy:
                    if h.module in enrich_map:
                        h.description = enrich_map[h.module]
                    for child in h.children:
                        if child.module in enrich_map:
                            child.description = enrich_map[child.module]
        except Exception:
            pass
        
        return hierarchy
    
    def _llm_hierarchical_workflows(
        self, workflows: List[BusinessWorkflow], entities: List[BusinessEntity],
        roles: List[UserRole]
    ) -> List[WorkflowHierarchy]:
        """用 LLM 推断工作流的层级关系"""
        # 构建供 LLM 分析的摘要
        workflow_info = []
        for w in workflows:
            workflow_info.append({
                'name': w.name,
                'module': w.owner,
                'trigger': w.trigger,
                'output': w.output,
                'steps_summary': [s[:80] for s in w.steps[:5]],
                'roles': w.roles_involved[:6],
                'step_count': len(w.steps),
            })
        
        entity_info = [{'name': e.name, 'purpose': e.purpose[:80]} for e in entities[:8]]
        role_info = [{'name': r.name, 'description': r.description[:60]} for r in roles[:15]]
        
        prompt = f"""你是一位**业务架构分析师**。请分析以下代码项目的工作流，找到"主轴"并按层级组织。

## 模块列表
{json.dumps(entity_info, ensure_ascii=False, indent=2)}

## 工作流列表
{json.dumps(workflow_info, ensure_ascii=False, indent=2)}

## 角色列表
{json.dumps(role_info, ensure_ascii=False, indent=2)}

## 任务
1. 找到项目的"主轴"——用户输入 → 核心处理 → 最终产出的主流程
2. 识别"一级子流程"——主轴调度/调用的独立流程
3. 识别"二级子流程"——一级子流程内部调用的更细粒度流程
4. 按层级组织：主轴(level=0) → 一级(level=1) → 二级(level=2)

## 层级判断规则
- 主轴：直接接收用户输入、对外暴露接口的流程（如 Web 端、主入口）
- 一级子流程：被主轴调度，有独立完整的业务逻辑（如洞察工具、调研工具）
- 二级子流程：被一级子流程调度，是更细粒度的子流程（如创意引擎被方案工具调度）
- 如果某个流程有明确的下游角色（如"小调调度调研工具"），说明它调度了另一个流程

## 返回 JSON 格式
```json
[
  {{
    "name": "层级节点名",
    "level": 0,
    "is_spine": true,
    "description": "这个层级做什么",
    "module": "所属模块",
    "trigger": "触发条件",
    "output": "产出物",
    "steps": ["关键步骤1", "关键步骤2"],
    "roles_involved": ["角色1", "角色2"],
    "children": [
      {{
        "name": "子层级名",
        "level": 1,
        "is_spine": false,
        "description": "...",
        "module": "...",
        "trigger": "...",
        "output": "...",
        "steps": [...],
        "roles_involved": [...],
        "children": []
      }}
    ]
  }}
]
```

注意：
- 主轴节点 is_spine=true，其他为 false
- level 从 0 开始递增
- 每个节点都要有 steps 和 roles_involved
- 如果工作流之间有明确的上下游关系，用 children 嵌套"""
        
        try:
            response = self.llm.chat_completion([
                {"role": "system", "content": "你是一个业务架构分析师。请仅返回JSON格式。"},
                {"role": "user", "content": prompt}
            ])
            
            json_match = re.search(r'```json\s*(.*?)\s*```', response, re.DOTALL)
            if not json_match:
                json_match = re.search(r'\[.*\]', response, re.DOTALL)
            
            if json_match:
                data = json.loads(json_match.group(1) if json_match.lastindex else json_match.group())
                return self._parse_hierarchy(data)
        except Exception as e:
            logger.warning(f"[BusinessAnalyzer] LLM 层级化解析失败: {e}")
        
        return self._rule_hierarchical_workflows(workflows, entities, roles)
    
    def _parse_hierarchy(self, data: list, level: int = 0) -> List[WorkflowHierarchy]:
        """递归解析层级 JSON"""
        result = []
        for item in data:
            node = WorkflowHierarchy(
                name=item.get('name', ''),
                level=item.get('level', level),
                description=item.get('description', ''),
                module=item.get('module', ''),
                steps=item.get('steps', []),
                trigger=item.get('trigger', ''),
                output=item.get('output', ''),
                roles_involved=item.get('roles_involved', []),
                is_spine=item.get('is_spine', False),
            )
            children = item.get('children', [])
            if children:
                node.children = self._parse_hierarchy(children, level=node.level + 1)
            result.append(node)
        return result
    
    def _rule_hierarchical_workflows(
        self, workflows: List[BusinessWorkflow], entities: List[BusinessEntity],
        roles: List[UserRole]
    ) -> List[WorkflowHierarchy]:
        """
        规则降级：按模块名+角色关系推测层级
        
        启发式规则（通用，不依赖特定项目）：
        1. 主轴 = 有 Web 入口或主入口的模块
        2. 一级 = 被主轴调度、有独立流程的模块
        3. 二级 = 被一级调度、角色数少的模块
        """
        # 构建角色→模块的映射
        role_modules = {}
        for r in roles:
            # 从角色描述中推断所属模块
            desc = r.description.lower()
            for e in entities:
                if e.technical_name.lower() in desc or e.name.lower() in desc:
                    role_modules[r.name] = e.technical_name
                    break
        
        # 按模块分组工作流
        module_workflows = defaultdict(list)
        for w in workflows:
            module_workflows[w.owner].append(w)
        
        # 找到主轴模块（有 Web 入口或主入口的）
        spine_modules = set()
        for e in entities:
            lower_name = e.technical_name.lower()
            if any(kw in lower_name for kw in ['web', 'main', 'app', 'entry', 'api']):
                spine_modules.add(e.technical_name)
            # 如果实体有 "Web端" 或 "GUI端" 等名字
            if any(kw in e.name for kw in ['Web', 'GUI', '入口', '主']):
                spine_modules.add(e.technical_name)
        
        # 如果没找到主轴，取文件数最多的实体作为主轴
        if not spine_modules and entities:
            max_entity = max(entities, key=lambda e: len(e.files))
            spine_modules.add(max_entity.technical_name)
        
        # 构建层级树
        hierarchy = []
        spine_children = []
        
        for module_name, wfs in module_workflows.items():
            # 找到模块对应的实体
            entity = next((e for e in entities if e.technical_name == module_name), None)
            entity_name = entity.name if entity else module_name
            
            # 检查是否为主轴
            is_spine = module_name in spine_modules
            
            # 构建该模块的层级节点
            if len(wfs) == 1:
                wf = wfs[0]
                node = WorkflowHierarchy(
                    name=entity_name,
                    level=0 if is_spine else 1,
                    description=entity.purpose if entity else wf.name,
                    module=module_name,
                    steps=wf.steps[:8],
                    trigger=wf.trigger,
                    output=wf.output,
                    roles_involved=wf.roles_involved[:8],
                    is_spine=is_spine,
                )
            else:
                # 多工作流的模块，创建父节点+子节点
                node = WorkflowHierarchy(
                    name=entity_name,
                    level=0 if is_spine else 1,
                    description=entity.purpose if entity else f"{len(wfs)} 个工作流",
                    module=module_name,
                    is_spine=is_spine,
                )
                for wf in wfs:
                    node.children.append(WorkflowHierarchy(
                        name=wf.name,
                        level=node.level + 1,
                        steps=wf.steps[:8],
                        trigger=wf.trigger,
                        output=wf.output,
                        roles_involved=wf.roles_involved[:8],
                        module=module_name,
                    ))
            
            if is_spine:
                hierarchy.append(node)
            else:
                spine_children.append(node)
        
        # 将非主轴节点挂在主轴下
        if hierarchy and spine_children:
            for h in hierarchy:
                h.children.extend(spine_children)
        
        return hierarchy
    
    def _workflows_from_prompt_analysis(self, pa: PromptAnalysisResult) -> List[BusinessWorkflow]:
        """将 Prompt 分析结果中的工作流转换为 BusinessWorkflow 列表"""
        workflows = []
        for w in pa.workflows:
            steps = [f"{s.get('order', '?')}. {s.get('role', '?')}: {s.get('action', '')[:80]}"
                    for s in w.steps]
            workflows.append(BusinessWorkflow(
                name=w.name,
                owner=w.module,
                steps=steps if steps else [f"{r}: {r}的职责" for r in w.roles_sequence],
                trigger=w.trigger,
                output=w.output,
                roles_involved=w.roles_sequence,
            ))
        return workflows
    
    def _heuristic_workflow_discovery(self, analysis, entities) -> List[BusinessWorkflow]:
        """
        发现业务流程（LLM + 知识库驱动，无硬编码流程关键词）
        
        核心改进：
        - 不再靠 "run/execute/process" 关键词匹配方法名
        - 通过知识库检索调用链，用 LLM 重建端到端业务流程
        - 当知识库不可用时，使用 docstring 分析作为降级方案
        """
        workflows = []
        
        # 优先使用知识库 + LLM 分析
        kb_analyzer = self._get_kb_analyzer()
        if kb_analyzer and self.llm and hasattr(self.llm, 'chat_completion'):
            try:
                kb_workflows = kb_analyzer.extract_workflows()
                if kb_workflows:
                    for w in kb_workflows:
                        workflows.append(BusinessWorkflow(
                            name=w.get("name", "未知流程"),
                            owner=w.get("entry", ""),
                            steps=w.get("steps", []),
                            trigger=w.get("description", ""),
                            output="",
                            roles_involved=[],
                        ))
                    if workflows:
                        return workflows
            except Exception as e:
                logger.warning(f"[BusinessAnalyzer] 知识库工作流发现失败: {e}")
        
        # 降级：从 docstring 和调用关系推断（不依赖硬编码关键词）
        for entity in entities:
            # 查找对应文件中的主要方法及其 docstring
            methods_with_docs = []
            for f in analysis.files:
                rel = os.path.relpath(f.file_path, analysis.project_path)
                if entity.technical_name in rel or entity.technical_name == os.path.dirname(rel):
                    for cls in f.classes:
                        for m in cls.methods:
                            if not m.name.startswith('_') and m.docstring:
                                methods_with_docs.append((m.name, m.docstring[:100]))
                    for fn in f.functions:
                        if not fn.name.startswith('_') and fn.docstring:
                            methods_with_docs.append((fn.name, fn.docstring[:100]))
            
            if methods_with_docs and len(methods_with_docs) >= 2:
                # 用 docstring 作为步骤描述
                steps = [f"{name}: {doc[:80]}" for name, doc in methods_with_docs[:8]]
                workflows.append(BusinessWorkflow(
                    name=f"{entity.name} 核心流程",
                    owner=entity.name,
                    steps=steps,
                    trigger=f"用户发起 {entity.name} 请求",
                    output=f"{entity.name} 产出结果",
                ))
        
        return workflows
    
    def _llm_workflow_discovery(self, analysis, entities, roles, enrichment=None) -> List[BusinessWorkflow]:
        """用 LLM 发现业务流程"""
        entity_desc = "\n".join(
            f"- {e.name}: {e.purpose}" for e in entities[:6]
        )
        role_desc = "\n".join(
            f"- {r.name}: {r.description}" for r in roles[:4]
        )

        # 查找关键流程代码
        flow_clues = self._extract_flow_clues(analysis)

        # GitNexus 调用链增强
        gn_call_chain = ""
        if enrichment and enrichment.available and enrichment.callee_index:
            chain_items = list(enrichment.callee_index.items())[:20]
            gn_call_chain = "\n【GitNexus 调用链关系】\n"
            for caller, callees in chain_items:
                gn_call_chain += f"  {caller} \u2192 {', '.join(callees[:5])}\n"
            if enrichment.entry_points:
                gn_call_chain += "\n【代码入口点】\n"
                for ep in enrichment.entry_points[:8]:
                    gn_call_chain += f"  - {ep}\n"

        learning_section = ""
        if self._prompt_memory:
            learning_section = f"\n【上一轮分析的经验】\n{self._prompt_memory[:1000]}\n请基于这些经验发现更深层的业务流程。\n"

        prompt = f"""你是一位**业务流程专家**。分析下面代码项目的业务实体和角色，发现其中的**业务流程**。

【业务实体】
{entity_desc}

【用户角色】
{role_desc}

【从代码中发现的工作流线索】
{flow_clues}
{gn_call_chain}
{learning_section}

【分析要求】
1. 每个流程要有明确的触发条件、步骤、产出物
2. 描述要**像产品说明书一样通俗**，非程序员也能看懂
3. 说出哪些角色参与了哪些步骤
4. 如果代码中有类似 "A流程/B流程/常规模式/深度模式" 等差异，分开描述
5. **重要**：优先使用 GitNexus 提供的调用链来构建精确步骤，而非猜测

请以 JSON 格式返回，仅返回 JSON：
{{
  "workflows": [
    {{
      "name": "流程名称",
      "owner": "所属业务实体",
      "steps": ["第1步: 做什么", "第2步: 做什么", "第3步: 做什么"],
      "trigger": "什么情况下触发这个流程",
      "output": "这个流程产出什么结果",
      "roles_involved": ["参与的角色1", "角色2"]
    }}
  ]
}}"""
        
        response = self._call_llm(prompt)
        return self._parse_llm_workflows(response)
    
    def _extract_flow_clues(self, analysis) -> str:
        """从代码中提取工作流线索"""
        clues = []
        
        # 查找包含 "step"、"flow"、"process"、"pipeline" 等关键词的类和函数
        flow_keywords = ['flow', 'step', 'pipeline', 'process', 'workflow', 
                        'routine', 'procedure', 'stage', 'phase']
        
        for f in analysis.files:
            for cls in f.classes:
                if any(k in cls.name.lower() for k in flow_keywords):
                    clues.append(
                        f"文件 {os.path.relpath(f.file_path, analysis.project_path)}: "
                        f"流程相关类 {cls.name}"
                    )
                for m in cls.methods:
                    if m.docstring and len(m.docstring) > 20:
                        clues.append(
                            f"方法 {cls.name}.{m.name}() 的注释: {m.docstring[:150]}"
                        )
            
            for fn in f.functions:
                if any(k in fn.name.lower() for k in flow_keywords):
                    clues.append(
                        f"文件 {os.path.relpath(f.file_path, analysis.project_path)}: "
                        f"流程相关函数 {fn.name}()"
                    )
                if fn.docstring and len(fn.docstring) > 20:
                    if any(k in fn.docstring.lower() for k in flow_keywords):
                        clues.append(f"函数 {fn.name}() 注释: {fn.docstring[:150]}")
        
        return "\n".join(clues[:20]) if clues else "（未发现明确的工作流代码注释）"
    
    def _parse_llm_workflows(self, response: str) -> List[BusinessWorkflow]:
        """解析 LLM 返回的工作流 JSON"""
        try:
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if not json_match:
                return []
            data = json.loads(json_match.group())
            return [
                BusinessWorkflow(
                    name=w.get("name", "未知流程"),
                    owner=w.get("owner", ""),
                    steps=w.get("steps", []),
                    trigger=w.get("trigger", ""),
                    output=w.get("output", ""),
                    roles_involved=w.get("roles_involved", []),
                )
                for w in data.get("workflows", [])
            ]
        except Exception as ex:
            logger.warning(f"[BusinessAnalyzer] 解析LLM工作流失败: {ex}")
            return []
    
    # ====================================================================
    #  Stage 3: 跨端与角色差异分析
    # ====================================================================
    
    def _discover_cross_cutting_differences(self, analysis, entities, roles, enrichment=None) -> List[CrossCuttingDifference]:
        """发现跨切面差异"""
        if self.llm and hasattr(self.llm, 'chat_completion'):
            return self._llm_difference_discovery(analysis, entities, roles, enrichment=enrichment)
        return self._heuristic_difference_discovery(analysis)
    
    def _heuristic_difference_discovery(self, analysis) -> List[CrossCuttingDifference]:
        """
        发现跨切面差异（LLM 驱动，无硬编码 gui/web 检查）
        """
        differences = []
        
        # 如果有 LLM，用 LLM 分析
        if self.llm and hasattr(self.llm, 'chat_completion'):
            # 收集 UI 相关的文件线索
            ui_clues = []
            has_gui = False
            has_web = False
            for f in analysis.files:
                lower_rel = f.file_path.lower()
                if 'gui' in lower_rel:
                    has_gui = True
                    ui_clues.append(f"GUI: {os.path.basename(f.file_path)}")
                if 'web' in lower_rel:
                    has_web = True
                    ui_clues.append(f"Web: {os.path.basename(f.file_path)}")
            
            if has_gui and has_web:
                try:
                    clues_text = "\n".join(ui_clues[:15])
                    prompt = f"""分析以下代码项目中的跨端/跨角色差异：
                    
UI线索:
{clues_text}

请分析 Web端 vs GUI端、不同用户角色之间的差异。返回 JSON 格式：
[{{"dimension": "对比维度", "aspect": "具体方面", "side_a": "A方", "side_b": "B方", "difference": "差异描述", "impact": "业务影响"}}]

如果没有明显差异，返回空数组 []。"""
                    result = self.llm.chat_completion([
                        {"role": "system", "content": "你是一个系统对比分析专家。请返回JSON格式。"},
                        {"role": "user", "content": prompt}
                    ])
                    json_match = re.search(r'\[.*\]', result, re.DOTALL)
                    if json_match:
                        diff_data = json.loads(json_match.group())
                        for d in diff_data:
                            differences.append(CrossCuttingDifference(
                                dimension=d.get("dimension", ""),
                                aspect=d.get("aspect", ""),
                                side_a=d.get("side_a", ""),
                                side_b=d.get("side_b", ""),
                                difference=d.get("difference", ""),
                                impact=d.get("impact", ""),
                            ))
                        if differences:
                            return differences
                except Exception:
                    pass
        
        # 降级：基本检测（不硬编码具体的差异描述）
        has_gui = any('gui' in f.file_path.lower() for f in analysis.files)
        has_web = any('web' in f.file_path.lower() for f in analysis.files)
        
        if has_gui and has_web:
            differences.append(CrossCuttingDifference(
                dimension="UI平台",
                aspect="交互方式",
                side_a="桌面GUI",
                side_b="Web端",
                difference="项目中同时存在 GUI 和 Web 两种交互方式",
                impact="不同用户群体可通过不同终端访问系统功能",
            ))
        
        return differences
    
    def _llm_difference_discovery(self, analysis, entities, roles, enrichment=None) -> List[CrossCuttingDifference]:
        """用 LLM 发现差异"""
        entity_desc = "\n".join(f"- {e.name}" for e in entities[:8])
        role_desc = "\n".join(f"- {r.name} ({r.description[:50]})" for r in roles[:4])

        # 查找 GUI/Web 文件线索
        ui_clues = self._find_ui_clues(analysis)

        # GitNexus 跨文件符号引用
        gn_cross_ref = ""
        if enrichment and enrichment.available and enrichment.file_symbols:
            # 找出有多个文件引用的符号（跨文件调用）
            cross_file_syms = {}
            for fp, syms in enrichment.file_symbols.items():
                for s in syms:
                    name = s.get("name", "")
                    if name:
                        cross_file_syms.setdefault(name, []).append(fp)
            shared_syms = {k: v for k, v in cross_file_syms.items() if len(v) >= 2}
            if shared_syms:
                gn_cross_ref = "\n【跨文件共享的符号（可能对应跨端/跨角色功能）】\n"
                for name, files in list(shared_syms.items())[:8]:
                    gn_cross_ref += f"- {name}: {', '.join(files[:3])}\n"

        learning_section = ""
        if self._prompt_memory:
            learning_section = f"\n【上一轮分析的经验与改进方向】\n{self._prompt_memory[:1000]}\n请基于这些经验发现更深层的跨端差异。\n"

        prompt = f"""你是一位**系统对比分析师**。分析下面的代码项目，找出不同平台、不同角色之间的**差异**。

【业务实体】
{entity_desc}

【用户角色】
{role_desc}

【跨端线索】
{ui_clues}
{gn_cross_ref}
{learning_section}

【分析要求】
1. 重点寻找：Web端 vs 桌面端的差异、不同用户角色的权限差异
2. 也找不同"模式"之间的差异（如普通模式 vs 深度模式）
3. 用通俗语言描述差异对"使用者"的影响
4. 如果代码中完全没有这些差异，如实回答"未发现差异"
5. **重要**：优先使用 GitNexus 提供的跨文件共享符号来判断哪些功能跨端存在

请以 JSON 格式返回，仅返回 JSON：
{{
  "differences": [
    {{
      "dimension": "对比维度（如 UI平台 / 用户角色 / 工作模式）",
      "aspect": "对比的具体方面",
      "side_a": "对比方A的描述",
      "side_b": "对比方B的描述",
      "difference": "差异的具体说明",
      "impact": "对业务使用的影响"
    }}
  ]
}}"""
        
        response = self._call_llm(prompt)
        return self._parse_llm_differences(response)
    
    def _find_ui_clues(self, analysis) -> str:
        """查找 UI 相关线索"""
        clues = []
        
        for f in analysis.files:
            rel = os.path.relpath(f.file_path, analysis.project_path)
            lower_rel = rel.lower()
            if 'gui' in lower_rel or 'web' in lower_rel or 'ui' in lower_rel:
                # 查找关键类
                class_names = [c.name for c in f.classes[:3]]
                func_names = [fn.name for fn in f.functions[:3]]
                if class_names or func_names:
                    details = ' | '.join(
                        (['类: ' + ', '.join(class_names)] if class_names else []) +
                        (['函数: ' + ', '.join(func_names)] if func_names else [])
                    )
                    clues.append(f"📄 {rel}: {details}")
        
        return "\n".join(clues[:10]) if clues else "（未发现明显 UI 界面代码）"
    
    def _parse_llm_differences(self, response: str) -> List[CrossCuttingDifference]:
        """解析LLM返回的差异JSON"""
        try:
            json_match = re.search(r'\{.*\}', response, re.DOTALL)
            if not json_match:
                return []
            data = json.loads(json_match.group())
            return [
                CrossCuttingDifference(
                    dimension=d.get("dimension", "未知"),
                    aspect=d.get("aspect", ""),
                    side_a=d.get("side_a", ""),
                    side_b=d.get("side_b", ""),
                    difference=d.get("difference", ""),
                    impact=d.get("impact", ""),
                )
                for d in data.get("differences", [])
            ]
        except Exception as ex:
            logger.warning(f"[BusinessAnalyzer] 解析LLM差异失败: {ex}")
            return []
    
    # ====================================================================
    #  Stage 4: 自评估
    # ====================================================================
    
    def _evaluate_quality(self, result: BusinessAnalysisResult) -> AnalysisEvaluation:
        """
        自我评估分析质量
        V2 — 通用版：
        - 不硬编码任何项目的预期特征（角色、工作流、跨端差异）
        - 只评估"你分析出来的东西质量如何"，不扣"缺了什么"的分
        - 评分维度：
          * 实体描述完整性：已有的实体是否说得清楚
          * 角色描述完整性：已有的角色是否描述充分
          * 工作流描述完整性：已有的流程是否步骤清晰
          * 差异描述完整性：已有的差异是否说明清楚
          * 整体一致性：报告覆盖了哪些维度
        """
        issues = []
        quality_points = 0
        total_checks = 0
        
        # 1. 实体质量：已有的实体是否有清晰描述
        total_checks += 1
        if result.entities:
            good_entities = [e for e in result.entities if len(e.purpose) > 5 and len(e.capabilities) > 0]
            good_ratio = len(good_entities) / len(result.entities)
            if good_ratio >= 0.7:
                quality_points += 1  # 大部分实体描述清晰
            elif good_ratio >= 0.3:
                quality_points += 0.5
                issues.append(f"部分业务实体（{len(result.entities) - len(good_entities)}个）缺少详细描述")
            else:
                issues.append("业务实体描述过于笼统")
        else:
            issues.append("未发现任何业务实体")
        
        # 2. 角色质量：已有的角色是否有描述
        total_checks += 1
        if result.roles:
            good_roles = [r for r in result.roles if len(r.description) > 5]
            if len(good_roles) == len(result.roles):
                quality_points += 1
            else:
                quality_points += 0.5
                issues.append(f"{len(result.roles) - len(good_roles)} 个角色描述不完整")
        else:
            # 不扣分——很多项目根本没有多角色概念
            quality_points += 0.8  # 中性处理：不扣分，也不给满分
        
        # 3. 工作流质量：已有的流程是否步骤清晰
        total_checks += 1
        if result.workflows:
            good_flows = [w for w in result.workflows if len(w.steps) >= 2]
            if len(good_flows) == len(result.workflows):
                quality_points += 1
            elif len(good_flows) > 0:
                quality_points += 0.5
                issues.append("部分业务流程步骤描述不完整")
            else:
                issues.append("业务流程缺少步骤说明")
        else:
            # 不扣分——很多项目没有"流程"概念（如工具库、配置中心）
            quality_points += 0.8
        
        # 4. 差异质量：已有的差异是否说明清楚
        total_checks += 1
        if result.differences:
            good_diffs = [d for d in result.differences if len(d.difference) > 10]
            if len(good_diffs) == len(result.differences):
                quality_points += 1
            else:
                quality_points += 0.5
                issues.append("部分差异描述不完整")
        else:
            # 不扣分——很多项目只有一个平台、一种角色
            quality_points += 0.8
        
        # 5. 报告覆盖率：报告覆盖了几个维度
        total_checks += 1
        covered = 0
        if result.entities: covered += 1
        if result.roles: covered += 1
        if result.workflows: covered += 1
        if result.differences: covered += 1
        coverage_ratio = covered / 4
        quality_points += coverage_ratio  # 0.25 ~ 1.0
        
        # 最终得分 = 质量分 / 总分
        max_score = total_checks + 1  # +1 是覆盖率
        score = quality_points / max_score
        
        # 有迭代提升加分
        if result.iteration_count > 1:
            score = min(1.0, score + 0.05)

        # GitNexus 增强加分
        if result.enrichment and result.enrichment.available:
            if result.enrichment.call_pairs:
                score = min(1.0, score + 0.08)  # 有调用链数据加分
            if result.enrichment.entry_points:
                score = min(1.0, score + 0.04)  # 有入口点加分

        score = max(0.0, min(1.0, score))
        passed = score >= 0.8
        
        suggestions = self._generate_evaluation_suggestions(issues)
        
        return AnalysisEvaluation(
            passed=passed,
            score=score,
            issues=issues,
            suggestions=suggestions,
        )
    
    def _generate_evaluation_suggestions(self, issues: List[str]) -> List[str]:
        """根据问题生成改进建议"""
        suggestion_map = {
            "未发现任何业务实体": "从文件名和类名推断业务含义，关注目录结构中的业务模块划分",
            "业务实体描述过于笼统": "从类注释和函数 docstring 中提取更多业务语义",
            "部分业务实体（": "从类注释和函数 docstring 中补充业务描述",
            "缺少详细描述": "从类注释和函数 docstring 中补充业务描述",
            "角色描述不完整": "从配置文件和认证相关代码提取更多角色信息",
            "部分业务流程步骤描述不完整": "深入分析方法调用链和参数",
            "业务流程缺少步骤说明": "关注 run/execute/process 等主流程方法",
            "部分差异描述不完整": "对比不同目录下的文件功能差异",
        }
        
        result = []
        for issue in issues:
            matched = False
            for key, sug in suggestion_map.items():
                if key in issue:
                    result.append(sug)
                    matched = True
                    break
            if not matched:
                result.append(f"改进: {issue}")
        
        return result
    
    # ====================================================================
    #  Stage 5: 自改进
    # ====================================================================
    
    def _generate_improvement(self, result: BusinessAnalysisResult,
                              evaluation: AnalysisEvaluation) -> str:
        """
        核心自学习方法：
        1. LLM 分析当前轮的结果（发现了什么、缺少了什么）
        2. LLM 基于分析「硬编码」一个更好的 Prompt
        3. 下一轮分析将使用这个改进后的 Prompt
        """
        # 构建当前分析摘要
        entity_summary = "\n".join(
            f"- {e.name} ({e.technical_name}): {e.purpose} [{'; '.join(e.capabilities[:3])}]"
            for e in result.entities[:8]
        ) if result.entities else "（无）"
        
        role_summary = "\n".join(
            f"- {r.name}: {r.description[:60]}"
            for r in result.roles[:5]
        ) if result.roles else "（无）"
        
        workflow_summary = "\n".join(
            f"- {w.name}: {len(w.steps)}步 | {w.trigger[:50]}"
            for w in result.workflows[:5]
        ) if result.workflows else "（无）"
        
        diff_summary = "\n".join(
            f"- {d.dimension}/{d.aspect}: {d.difference[:60]}"
            for d in result.differences[:5]
        ) if result.differences else "（无）"
        
        # 没有 LLM 时，走规则式改进
        if not self.llm or not hasattr(self.llm, 'chat_completion'):
            issues_text = "、".join(evaluation.issues) if evaluation.issues else "无明确问题"
            return (
                f"【规则式自改进】\n"
                f"当前不足: {issues_text}\n"
                f"改进建议: {'; '.join(evaluation.suggestions)}\n"
                f"历史得分: {', '.join(f'{s:.2f}' for s in result.evaluation_scores)}"
            )
        
        # 有 LLM 时：让 LLM 硬编码一个更好的 Prompt
        prompt = f"""你是一位**资深业务架构师 + 提示词工程师**。你刚刚完成了一轮代码业务分析，但结果不够理想。

## 当前分析结果

【已发现的业务实体】
{entity_summary}

【已发现的用户角色】
{role_summary}

【已发现的业务流程】
{workflow_summary}

【已发现的跨端差异】
{diff_summary}

## 自评估发现问题
{chr(10).join(f'- {i}' for i in evaluation.issues)}

## 你的任务
请**硬编码一份改进后的分析 Prompt**，用于下一轮分析。

要求：
1. 基于你到现在对代码项目的理解，写出更有针对性的分析指示
2. 明确指出上一轮分析中遗漏了什么、应该关注什么
3. 用「业务分析师」的口吻，引导下一轮分析更深入地发现业务概念
4. **直接输出改进后的 Prompt 文本**，不要任何包裹

关键改进方向：
- 如果缺少业务实体 → 引导下一轮分析更仔细地识别模块边界
- 如果缺少用户角色 → 引导关注 "admin/user/role/permission" 等关键词和认证相关代码
- 如果缺少业务流程 → 引导关注方法调用链、主流程类、run/execute/process 等方法
- 如果缺少跨端差异 → 引导关注 gui/ web/ 目录差异和不同入口文件的功能对比

输出格式（直接输出，不要使用代码块）：
【第{result.iteration_count + 1}轮改进版分析指示】
[你的硬编码 Prompt 内容]"""
        
        try:
            improved_prompt = self.llm.chat_completion([
                {"role": "system", "content": "你是一位提示词工程师和业务架构师。你擅长分析代码分析结果，发现不足，并硬编码更好的分析提示词。"},
                {"role": "user", "content": prompt}
            ])
            return improved_prompt.strip()
        except Exception as e:
            issues_text = "、".join(evaluation.issues) if evaluation.issues else "无明确问题"
            return (
                f"【LLM自改进失败，回退规则式】\n"
                f"错误: {e}\n"
                f"当前不足: {issues_text}\n"
                f"改进方向: {'; '.join(evaluation.suggestions)}"
            )
    
    # ====================================================================
    #  报告生成
    # ====================================================================
    
    def to_business_report(self, result: BusinessAnalysisResult) -> str:
        """
        生成专业级业务全景报告 V2
        核心改进：
        1. 系统架构总览图（Mermaid）
        2. 业务流程图（Mermaid 流程图）
        3. 模块关系矩阵
        4. 角色-功能权限矩阵
        5. 数据流向图
        """
        lines = []
        
        def _a(title):
            lines.append('')
            lines.append(f'## {title}')
            lines.append('')
        
        def _h3(title):
            lines.append(f'### {title}')
            lines.append('')
        
        def _table(headers, rows):
            sep = '|' + '|'.join(['---'] * len(headers)) + '|'
            lines.append('| ' + ' | '.join(headers) + ' |')
            lines.append(sep)
            for row in rows:
                lines.append('| ' + ' | '.join(str(c) for c in row) + ' |')
            lines.append('')
        
        # 过滤非业务实体
        _skip = {'测试', '根模块', '方案待处理', 'root', 'tests', 'test', 'node_modules', '__pycache__'}
        entities = [e for e in result.entities 
                    if e.technical_name.lower() not in _skip and e.name not in _skip]
        
        # ================================================================
        #  头部
        # ================================================================
        project_display = result.project_name
        
        lines.append(f'# {project_display} — 业务架构全景报告')
        lines.append('')
        lines.append(f'> **报告日期**：{__import__("datetime").datetime.now().strftime("%Y-%m-%d %H:%M")}')
        lines.append(f'> **分析引擎**：CodeRef AI BusinessAnalyzer V2.1 + GitNexus Code Intelligence')
        lines.append(f'> **代码规模**：{result.file_count} 文件 / {result.line_count:,} 行 / {result.total_classes} 类 / {result.total_functions} 函数')
        if result.enrichment and result.enrichment.available:
            lines.append(f'> **GitNexus 索引**：{len(result.enrichment.all_symbols)} 符号 / {len(result.enrichment.call_pairs)} 调用关系 / {len(result.enrichment.entry_points)} 入口点')
        lines.append('')
        lines.append('---')
        lines.append('')
        
        # ================================================================
        #  一、系统架构总览
        # ================================================================
        _a('一、系统架构总览')
        
        lines.append('### 1.1 架构全景图')
        lines.append('')
        lines.append('```mermaid')
        lines.append('graph TB')
        lines.append('    subgraph 用户层')
        lines.append('        U1[营销人员/Web端]')
        lines.append('        U2[管理员/GUI端]')
        lines.append('    end')
        lines.append('')
        lines.append('    subgraph 业务工具层')
        # 为每个实体生成节点
        for e in entities[:8]:
            node_id = e.technical_name.replace('-', '_').replace(' ', '_')[:20]
            lines.append(f'        {node_id}[{e.name}]')
        lines.append('    end')
        lines.append('')
        lines.append('    subgraph 共享服务层')
        lines.append('        S1[LLM客户端]')
        lines.append('        S2[搜索服务]')
        lines.append('        S3[文档处理]')
        lines.append('        S4[配置中心]')
        lines.append('        S5[安全审计]')
        lines.append('    end')
        lines.append('')
        lines.append('    subgraph 基础设施层')
        lines.append('        I1[配置管理]')
        lines.append('        I2[日志监控]')
        lines.append('        I3[数据存储]')
        lines.append('    end')
        lines.append('')
        # 添加依赖关系（动态生成，不硬编码）
        for e in entities[:8]:
            node_id = e.technical_name.replace('-', '_').replace(' ', '_')[:20]
            lines.append(f'    {node_id} --> S1')
            lines.append(f'    {node_id} --> S4')
        lines.append('    U1 --> S1')
        lines.append('    U2 --> S4')
        lines.append('    S1 --> I1')
        lines.append('    S4 --> I1')
        lines.append('```')
        lines.append('')
        
        # 架构分层说明（动态生成，不硬编码模块名）
        lines.append('### 1.2 架构分层说明')
        lines.append('')
        lines.append('| 层级 | 模块 | 职责 |')
        lines.append('|------|------|------|')
        top_entity_names = '、'.join(e.name for e in entities[:6]) if entities else '业务模块'
        layers = [
            ('用户交互层', 'Web端 / GUI端 / API', '提供用户界面，接收用户输入，展示分析结果'),
            ('业务层', top_entity_names, '承载核心业务逻辑，执行具体任务'),
            ('共享服务层', 'LLM客户端 / 搜索服务 / 文档处理 / 配置中心', '提供通用能力，被多个业务模块复用'),
            ('基础设施层', '配置管理 / 日志监控 / 数据存储', '提供底层支撑，保障系统稳定运行'),
        ]
        for layer, mods, duty in layers:
            lines.append(f'| **{layer}** | {mods} | {duty} |')
        lines.append('')
        
        # ================================================================
        #  二、业务模块详解
        # ================================================================
        _a('二、业务模块详解')
        
        for idx, entity in enumerate(entities, 1):
            entity_wfs = [wf for wf in result.workflows if wf.owner == entity.name or wf.owner == entity.technical_name]
            
            _h3(f'{idx}. {entity.name} `{entity.technical_name}`')
            
            # 功能定位表格
            lines.append('| 属性 | 内容 |')
            lines.append('|------|------|')
            lines.append(f'| **业务定位** | {entity.purpose or "核心业务组件"} |')
            caps = '、'.join(entity.capabilities[:5]) if entity.capabilities else '-'
            lines.append(f'| **核心能力** | {caps} |')
            classes = '、'.join(entity.core_classes[:5]) if entity.core_classes else '-'
            lines.append(f'| **关键类** | {classes} |')
            files = f'{len(entity.files)} 个文件' if entity.files else '-'
            lines.append(f'| **代码规模** | {files} |')
            lines.append('')
            
            # 如果有工作流，展示流程图
            for wf in entity_wfs[:2]:
                lines.append(f'**业务流程：{wf.name}**')
                lines.append('')
                lines.append('```mermaid')
                lines.append('flowchart LR')
                # 生成流程图节点
                for i, step in enumerate(wf.steps[:8]):
                    step_clean = step.replace('"', "'")[:30]
                    lines.append(f'    S{i}["{step_clean}"]')
                # 连接箭头
                for i in range(len(wf.steps[:8]) - 1):
                    lines.append(f'    S{i} --> S{i+1}')
                lines.append('```')
                lines.append('')
                lines.append(f"- **触发条件**：{wf.trigger or '用户发起请求'}")
                lines.append(f"- **产出物**：{wf.output or '业务结果'}")
                if wf.roles_involved:
                    lines.append(f"- **参与角色**：{'、'.join(wf.roles_involved)}")
                lines.append('')
        
        # ================================================================
        #  三、核心业务流程（层级化）
        # ================================================================
        _a('三、核心业务流程（按层级捋清楚）')
        
        if result.hierarchy:
            # 3.1 层级总览
            lines.append('### 3.1 业务层级总览')
            lines.append('')
            lines.append('> 按 **主轴 → 一级子流程 → 二级子流程 → 角色步骤** 的层级组织，模拟 AI 直读代码的思考方式。')
            lines.append('')
            
            # 构建层级树文本
            for node in result.hierarchy:
                spine_marker = ' 🔵 **主轴**' if node.is_spine else ''
                lines.append(f'### 3.{result.hierarchy.index(node)+2} {node.name}{spine_marker}')
                lines.append('')
                if node.description:
                    lines.append(f'{node.description}')
                    lines.append('')
                
                # 步骤表格
                if node.steps:
                    lines.append('| 步骤 | 说明 |')
                    lines.append('|------|------|')
                    for i, step in enumerate(node.steps):
                        lines.append(f'| {i+1} | {step[:100]} |')
                    lines.append('')
                
                if node.roles_involved:
                    roles_str = ' → '.join(node.roles_involved[:8])
                    lines.append(f'**涉及角色**：{roles_str}')
                    lines.append('')
                
                if node.trigger:
                    lines.append(f'**触发条件**：{node.trigger}')
                    lines.append('')
                if node.output:
                    lines.append(f'**产出物**：{node.output}')
                    lines.append('')
                
                # 递归输出子层级
                if node.children:
                    self._render_hierarchy_children(lines, node.children, indent_level=1)
            
            # 3.2 层级化 Mermaid 流程图
            lines.append('### 3.2 层级化业务流程')
            lines.append('')
            lines.append('```mermaid')
            lines.append('flowchart TB')
            lines.append('    Start([用户输入])')
            
            node_counter = [0]
            for node in result.hierarchy:
                self._render_hierarchy_mermaid(lines, node, "Start", node_counter)
            
            lines.append('```')
            lines.append('')
            
        elif result.workflows:
            # 降级：平面输出
            lines.append('### 3.1 流程总览')
            lines.append('')
            lines.append('| 流程名称 | 所属模块 | 步骤数 | 触发条件 | 产出物 |')
            lines.append('|----------|----------|--------|----------|--------|')
            for wf in result.workflows:
                steps = len(wf.steps)
                trigger = wf.trigger[:30] + '...' if len(wf.trigger) > 30 else wf.trigger
                output = wf.output[:30] + '...' if len(wf.output) > 30 else wf.output
                lines.append(f'| {wf.name} | {wf.owner} | {steps} | {trigger or "-"} | {output or "-"} |')
            lines.append('')
        else:
            lines.append('（未识别到明确的业务流程）')
            lines.append('')
        
        # ================================================================
        #  四、用户角色与权限
        # ================================================================
        _a('四、用户角色与权限')
        
        if result.roles:
            lines.append('### 4.1 角色定义')
            lines.append('')
            lines.append('| 角色 | 描述 | 权限级别 | 可访问功能 | 界面 |')
            lines.append('|------|------|----------|------------|------|')
            for r in result.roles:
                features = '、'.join(r.accessible_features[:4]) if r.accessible_features else '-'
                lines.append(f'| **{r.name}** | {r.description[:40]} | {r.access_level} | {features} | {r.ui_mode or "-"} |')
            lines.append('')
            
            # 角色-功能矩阵
            if len(result.roles) >= 2 and entities:
                lines.append('### 4.2 角色-功能权限矩阵')
                lines.append('')
                lines.append('| 功能 / 角色 | ' + ' | '.join(r.name for r in result.roles) + ' |')
                lines.append('|' + '|'.join(['---'] * (len(result.roles) + 1)) + '|')
                
                # 为每个实体生成权限行
                for e in entities[:8]:
                    row = [e.name]
                    for r in result.roles:
                        # 简单启发：如果角色可访问功能中包含实体名，或高权限角色可以访问所有
                        has_access = any(e.name in f or e.technical_name in f for f in r.accessible_features)
                        if r.access_level == '高' or has_access:
                            row.append('✅')
                        else:
                            row.append('❌')
                    lines.append('| ' + ' | '.join(row) + ' |')
                lines.append('')
        else:
            lines.append('（未识别到多角色设计）')
            lines.append('')
        
        # ================================================================
        #  五、模块间依赖关系
        # ================================================================
        _a('五、模块间依赖关系')
        
        if result.enrichment and result.enrichment.available:
            callee = result.enrichment.callee_index
            
            lines.append('### 5.1 调用关系矩阵')
            lines.append('')
            
            # 提取模块级调用关系
            mod_calls = defaultdict(lambda: defaultdict(int))
            entry_mods = defaultdict(int)
            
            for ep in result.enrichment.entry_points:
                parts = ep.replace('\\', '/').split('/')
                if parts:
                    entry_mods[parts[0]] += 1
            
            if callee:
                for caller, callees in list(callee.items())[:50]:
                    caller_mod = caller.split('.')[0] if '.' in caller else caller.split('/')[0] if '/' in caller else caller
                    for cal in callees[:10]:
                        cal_mod = cal.split('.')[0] if '.' in cal else cal.split('/')[0] if '/' in cal else cal
                        if caller_mod != cal_mod:
                            mod_calls[caller_mod][cal_mod] += 1
            
            # 展示 TOP 调用关系
            if mod_calls:
                lines.append('| 调用方 | 被调用方 | 调用次数 | 关系类型 |')
                lines.append('|--------|----------|----------|----------|')
                relations = []
                for caller_mod, callees in mod_calls.items():
                    for cal_mod, count in callees.items():
                        rel_type = '服务依赖' if any(s in cal_mod.lower() for s in ['shared', 'config', 'common']) else '业务协作'
                        relations.append((caller_mod, cal_mod, count, rel_type))
                
                relations.sort(key=lambda x: -x[2])
                for caller, callee, count, rel_type in relations[:15]:
                    lines.append(f'| `{caller}` | `{callee}` | {count} | {rel_type} |')
                lines.append('')
            
            # 入口点分布
            if entry_mods:
                lines.append('### 5.2 系统入口点分布')
                lines.append('')
                lines.append('| 模块 | 入口点数量 | 说明 |')
                lines.append('|------|------------|------|')
                for mod, count in sorted(entry_mods.items(), key=lambda x: -x[1])[:8]:
                    lines.append(f'| `{mod}` | {count} | 主要业务入口 |')
                lines.append('')
        else:
            lines.append('（未启用 GitNexus 增强，无法提供精确的调用关系分析）')
            lines.append('')
        
        # ================================================================
        #  六、跨端/跨角色差异
        # ================================================================
        _a('六、跨端与角色差异')
        
        if result.differences:
            for d in result.differences:
                _h3(f'{d.dimension} — {d.aspect}')
                lines.append(f'| | {d.side_a} | {d.side_b} |')
                lines.append(f'|------|------|------|')
                lines.append(f'| **差异** | {d.difference[:50]} | - |')
                lines.append(f'| **影响** | {d.impact[:50] if d.impact else "-"} | - |')
                lines.append('')
        else:
            lines.append('（未识别到显著的跨端或跨角色差异）')
            lines.append('')
        
        # ================================================================
        #  七、关键发现与建议
        # ================================================================
        _a('七、关键发现与建议')
        
        # 计算评分
        score = 70
        if entities and len(entities) >= 3: score += 10
        if result.workflows and len(result.workflows) >= 2: score += 5
        if result.roles and len(result.roles) >= 2: score += 5
        if result.enrichment and result.enrichment.available: score += 5
        if result.evaluation_scores:
            avg_eval = sum(result.evaluation_scores) / len(result.evaluation_scores)
            score = int(score * 0.6 + avg_eval * 100 * 0.4)
        score = max(50, min(95, score))
        grade = '优秀' if score >= 85 else '良好' if score >= 70 else '一般' if score >= 60 else '待改进'
        
        lines.append(f'**总体评分：{score}/100 ({grade})**')
        lines.append('')
        
        lines.append('### 7.1 架构优势')
        lines.append('')
        if len(entities) >= 3:
            lines.append(f'1. **模块化设计**：系统划分为 {len(entities)} 个明确的功能模块，职责清晰')
        if result.workflows:
            lines.append(f'2. **业务流程闭环**：定义了 {len(result.workflows)} 条核心业务流程')
        if result.enrichment and result.enrichment.available:
            lines.append(f'3. **调用链清晰**：GitNexus 索引显示 {len(result.enrichment.call_pairs)} 条调用关系，架构呈有向无环特征')
        lines.append('')
        
        lines.append('### 7.2 改进建议')
        lines.append('')
        avg_line = result.line_count / max(result.file_count, 1)
        if avg_line > 300:
            lines.append(f'1. **文件拆分**：平均每文件 {avg_line:.0f} 行，建议拆分超过 500 行的大文件')
        if not result.enrichment or not result.enrichment.available:
            lines.append('2. **启用 GitNexus**：获取精确的调用链和依赖关系分析')
        lines.append('3. **自动化测试**：为各引擎核心逻辑编写单元测试，使用 MockLLMClient 避免 LLM 调用成本')
        lines.append('')
        
        lines.append('---')
        lines.append(f'*报告由 CodeRef-AI BusinessAnalyzer V2.1 生成 · 迭代 {result.iteration_count} 轮 · GitNexus 增强 {"启用" if result.enrichment and result.enrichment.available else "未启用"}*')
        
        return '\n'.join(lines)
    
    # ====================================================================
    #  LLM 调用辅助
    # ====================================================================

    def _build_report_data_summary(self, result: BusinessAnalysisResult) -> str:
        """构建紧凑的数据摘要，供 LLM 润色报告时参考"""
        parts = []
        
        # 实体数据
        if result.entities:
            parts.append("【业务模块】")
            for e in result.entities[:10]:
                caps = '; '.join(e.capabilities[:4]) if e.capabilities else '无'
                classes = ', '.join(e.core_classes[:4]) if e.core_classes else '无'
                files_count = len(e.files)
                parts.append(f"- {e.name}({e.technical_name}): {e.purpose} | 能力: {caps} | 关键类: {classes} | 文件数: {files_count}")
        
        # 工作流
        if result.workflows:
            parts.append("\n【业务流程】")
            for w in result.workflows[:8]:
                steps = ' → '.join(w.steps[:4])
                parts.append(f"- {w.name}: {w.trigger} → {steps} → {w.output} | 角色: {', '.join(w.roles_involved)}")
        
        # 差异
        if result.differences:
            parts.append("\n【跨端/跨角色差异】")
            for d in result.differences[:6]:
                parts.append(f"- {d.dimension}/{d.aspect}: {d.side_a} vs {d.side_b} → {d.difference}")
        
        # GitNexus 调用链 TOP 引用
        if result.enrichment and result.enrichment.available and result.enrichment.callee_index:
            parts.append("\n【GitNexus 调用链 Top 15（被调用最多的符号）】")
            call_count = {}
            for caller, callees in result.enrichment.callee_index.items():
                for callee in callees:
                    call_count[callee] = call_count.get(callee, 0) + 1
            sorted_calls = sorted(call_count.items(), key=lambda x: -x[1])[:15]
            for name, count in sorted_calls:
                parts.append(f"- {name}: 被调用 {count} 次")
            
            # 跨模块依赖
            file_calls = {}
            for caller, callees in result.enrichment.callee_index.items():
                for callee in callees:
                    caller_mod = caller.split('.')[0] if '.' in caller else caller
                    callee_mod = callee.split('.')[0] if '.' in callee else callee
                    if caller_mod != callee_mod:
                        key = f"{caller_mod} → {callee_mod}"
                        file_calls[key] = file_calls.get(key, 0) + 1
            if file_calls:
                parts.append("\n【跨模块调用 Top 10】")
                sorted_cross = sorted(file_calls.items(), key=lambda x: -x[1])[:10]
                for dep, count in sorted_cross:
                    parts.append(f"- {dep}: {count} 次")
        
        parts.append(f"\n【总数据】{result.file_count}文件, {result.line_count}行, {result.total_classes}类, {result.total_functions}函数, {len(result.entities)}模块, {len(result.workflows)}流程")
        
        return '\n'.join(parts)

    def _call_llm(self, prompt: str) -> str:
        """调用 LLM，支持重试"""
        if not self.llm or not hasattr(self.llm, 'chat_completion'):
            logger.warning("[BusinessAnalyzer] LLM 不可用，使用启发式分析结果")
            return json.dumps({"entities": [], "roles": [], "workflows": [], "differences": [],
                             "_llm_unavailable": True,
                             "_message": "LLM API Key 未配置或服务不可用，以下为启发式分析结果"})

        try:
            return self.llm.chat_completion([
                {"role": "system", "content": "你是一个代码分析专家，请分析代码并返回JSON格式结果"},
                {"role": "user", "content": prompt}
            ])
        except Exception as e:
            logger.error(f"[BusinessAnalyzer] LLM 调用失败: {e}")
            return json.dumps({"entities": [], "roles": [], "workflows": [], "differences": [],
                             "_llm_unavailable": True,
                             "_message": f"LLM 调用失败: {str(e)}，以下为启发式分析结果"})

    def _render_hierarchy_children(self, lines: List[str], children: List[WorkflowHierarchy], indent_level: int = 1):
        """递归渲染层级子节点"""
        indent = '  ' * indent_level
        sub_prefix = '├── ' if indent_level == 1 else '└── '
        for child in children:
            spine_marker = ' 🔵' if child.is_spine else ''
            lines.append(f'{indent}{sub_prefix}**{child.name}**{spine_marker}')
            if child.description:
                lines.append(f'{indent}    {child.description[:120]}')
            if child.steps:
                roles_inline = ' → '.join(child.roles_involved[:5]) if child.roles_involved else ''
                steps_str = ' → '.join(s[:50] for s in child.steps[:5])
                lines.append(f'{indent}    步骤: {steps_str}')
                if roles_inline:
                    lines.append(f'{indent}    角色: {roles_inline}')
            if child.children:
                self._render_hierarchy_children(lines, child.children, indent_level + 1)
            lines.append('')

    def _render_hierarchy_mermaid(self, lines: List[str], node: WorkflowHierarchy, parent_id: str, counter: List[int]):
        """渲染层级 Mermaid 节点"""
        counter[0] += 1
        node_id = f'N{counter[0]}'
        node_label = node.name[:25]
        spine_badge = ' [主轴]' if node.is_spine else ''
        lines.append(f'    {node_id}["{node_label}{spine_badge}"]')
        lines.append(f'    {parent_id} --> {node_id}')
        
        for child in node.children:
            self._render_hierarchy_mermaid(lines, child, node_id, counter)


# ========================================================================
#  便捷函数
# ========================================================================

def analyze_project_business(project_analysis, llm_client=None, max_iterations=3) -> str:
    """
    一键生成业务全景分析报告
    
    用法:
        from core.code_analyzer import CodeAnalyzer
        from core.business_analyzer import analyze_project_business
        
        analyzer = CodeAnalyzer()
        analysis = analyzer.analyze_project("/path/to/project")
        report = analyze_project_business(analysis)
        print(report)
    """
    ba = BusinessAnalyzer(llm_client=llm_client)
    result = ba.analyze(project_analysis, max_iterations=max_iterations)
    return ba.to_business_report(result)
