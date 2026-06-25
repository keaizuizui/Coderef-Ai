# -*- coding: utf-8 -*-
"""
LLM集成模块
支持OpenAI、DeepSeek、Ollama等多种模型
"""

import os
import json
from typing import Dict, List, Any, Optional, Literal
from dataclasses import dataclass, field
from enum import Enum

from loguru import logger
from openai import OpenAI


class LLMProvider(Enum):
    """LLM服务提供商"""
    OPENAI = "openai"
    DEEPSEEK = "deepseek"
    OLLAMA = "ollama"
    CUSTOM = "custom"


@dataclass
class LLMConfig:
    """LLM配置"""
    provider: LLMProvider
    api_key: str = ""
    base_url: str = ""
    model: str = ""
    temperature: float = 0.7
    max_tokens: int = 2048


@dataclass
class CodeSuggestion:
    """代码建议"""
    suggestion_id: str
    title: str
    description: str
    insert_position: Dict[str, Any] = field(default_factory=dict)
    code_snippet: str = ""
    reference_comment: str = ""
    modification_notes: List[str] = field(default_factory=list)
    risk_warnings: List[str] = field(default_factory=list)
    test_suggestions: List[str] = field(default_factory=list)
    source_reference: str = ""


class LLMIntegration:
    """LLM集成管理器"""
    
    def __init__(self, config: Optional[LLMConfig] = None):
        if config is None:
            config = self._load_config_from_settings()
        self.config = config
        self.client = None
        self._init_client()
    
    @staticmethod
    def _load_config_from_settings() -> LLMConfig:
        """
        加载 LLM 配置，按优先级尝试多个来源：
        1. 环境变量（CODEREF_API_KEY / CODEREF_BASE_URL / CODEREF_MODEL）
        2. QSettings（GUI 配置面板保存的，Windows 注册表）
        3. config/config.json（旧版配置文件，兼容）
        4. 默认值（DeepSeek）
        """
        # ── 优先级 1：环境变量 ──
        env_key = os.environ.get("CODEREF_API_KEY", "")
        if env_key:
            return LLMConfig(
                provider=LLMProvider(os.environ.get("CODEREF_PROVIDER", "deepseek")),
                api_key=env_key,
                base_url=os.environ.get("CODEREF_BASE_URL", "https://api.deepseek.com/v1"),
                model=os.environ.get("CODEREF_MODEL", "deepseek-chat"),
                temperature=float(os.environ.get("CODEREF_TEMPERATURE", "0.7")),
                max_tokens=int(os.environ.get("CODEREF_MAX_TOKENS", "4096")),
            )

        

        # ── 优先级 3：config/config.json（旧版配置文件，兼容） ──
        try:
            config_paths = [
                os.path.join(os.path.dirname(os.path.dirname(__file__)), "config", "config.json"),
                # 支持从项目根目录查找
                os.path.join(os.getcwd(), "config", "config.json"),
            ]
            for cfg_path in config_paths:
                if os.path.exists(cfg_path):
                    with open(cfg_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                    api_key = data.get("llm_api_key", "") or data.get("api_key", "")
                    if api_key and api_key != "ollama":  # "ollama" 是占位符，不算有效 key
                        provider_str = data.get("llm_provider", "deepseek")
                        provider_map = {
                            "deepseek": LLMProvider.DEEPSEEK,
                            "openai": LLMProvider.OPENAI,
                            "ollama": LLMProvider.OLLAMA,
                            "custom": LLMProvider.CUSTOM,
                        }
                        return LLMConfig(
                            provider=provider_map.get(provider_str, LLMProvider.DEEPSEEK),
                            api_key=api_key,
                            base_url=data.get("llm_base_url", data.get("base_url", "https://api.deepseek.com/v1")),
                            model=data.get("llm_model", data.get("model_name", "deepseek-chat")),
                            temperature=float(data.get("llm_temperature", data.get("temperature", 0.7))),
                            max_tokens=int(data.get("llm_max_tokens", data.get("max_tokens", 4096))),
                        )
                    else:
                        logger.debug(f"config.json 中 api_key 为占位符或空，跳过: {cfg_path}")
        except Exception as e:
            logger.debug(f"读取 config.json 失败: {e}")

        # ── 优先级 4：默认值（无 API Key） ──
        logger.debug("未找到有效的 LLM 配置（环境变量/QSettings/config.json 均无），LLM 功能暂不可用")
        return LLMConfig(
            provider=LLMProvider.DEEPSEEK,
            base_url="https://api.deepseek.com/v1",
            model="deepseek-chat",
            api_key=""
        )
    
    def _init_client(self):
        """初始化LLM客户端（无API Key时不初始化，留待用时提示）"""
        api_key = self.config.api_key or ""
        if not api_key:
            logger.debug("未设置API Key，LLM功能暂不可用")
            self.client = None
            return
        
        try:
            if self.config.provider == LLMProvider.OLLAMA:
                self.client = OpenAI(
                    base_url=self.config.base_url or "http://localhost:11434/v1",
                    api_key=api_key,
                    timeout=120, max_retries=1,
                )
            elif self.config.provider == LLMProvider.OPENAI:
                self.client = OpenAI(
                    api_key=api_key,
                    base_url=self.config.base_url or "https://api.openai.com/v1",
                    timeout=120, max_retries=1,
                )
            elif self.config.provider == LLMProvider.DEEPSEEK:
                self.client = OpenAI(
                    api_key=api_key,
                    base_url=self.config.base_url or "https://api.deepseek.com/v1",
                    timeout=120, max_retries=1,
                )
            else:
                self.client = OpenAI(
                    api_key=api_key,
                    base_url=self.config.base_url,
                    timeout=120, max_retries=1,
                )
            
            logger.info(f"LLM客户端初始化完成: {self.config.provider.value}")
        except Exception as e:
            logger.warning(f"LLM客户端初始化失败: {e}")
    
    def update_config(self, config: LLMConfig):
        """更新配置"""
        self.config = config
        self._init_client()
    
    def chat_completion(self, messages: List[Dict[str, str]], **kwargs) -> str:
        """执行聊天补全"""
        if not self.client:
            if not self.config.api_key:
                logger.warning("LLM不可用：未设置API Key。请在配置面板中填写API Key。")
                return "LLM调用错误: 未设置API Key，请在配置面板中填写"
            logger.error("LLM客户端未初始化")
            return "LLM调用错误: 客户端初始化失败"
        
        try:
            response = self.client.chat.completions.create(
                model=kwargs.get('model', self.config.model),
                messages=messages,
                temperature=kwargs.get('temperature', self.config.temperature),
                max_tokens=kwargs.get('max_tokens', self.config.max_tokens)
            )
            return response.choices[0].message.content or ""
        except Exception as e:
            logger.error(f"LLM调用失败: {e}")
            return f"LLM调用错误: {str(e)}"
    
    def analyze_code_context(self, code_content: str, file_path: str) -> Dict[str, Any]:
        """分析代码上下文"""
        prompt = f"""
分析以下代码文件，提供结构化的分析结果。

文件路径: {file_path}

代码内容:
```
{code_content[:5000]}
```

请以JSON格式返回分析结果，包含以下字段：
1. "file_purpose": 该文件的主要功能和用途
2. "key_functions": 关键函数列表
3. "code_style": 代码风格特点（命名规范、缩进、注释等）
4. "dependencies": 主要依赖
5. "insertion_points": 建议插入新代码的位置（包含行号和说明）
6. "optimization_points": 可优化的点

只返回JSON，不要其他解释。
"""
        
        response = self.chat_completion([
            {"role": "system", "content": "你是专业的代码分析专家，只返回JSON格式的分析结果。"},
            {"role": "user", "content": prompt}
        ])
        
        try:
            # 尝试提取JSON
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                return json.loads(response[json_start:json_end])
        except (json.JSONDecodeError, KeyError, ValueError):
            pass
        
        return {
            "file_purpose": "代码分析",
            "key_functions": [],
            "code_style": "standard",
            "dependencies": [],
            "insertion_points": [],
            "optimization_points": []
        }
    
    def generate_code_suggestion(
        self,
        current_code: str,
        reference_content: str,
        reference_source: str,
        insert_hint: str = ""
    ) -> CodeSuggestion:
        """生成代码借鉴建议"""
        
        prompt = f"""
基于参考资源，为现有代码生成借鉴建议。

## 当前代码
```
{current_code[:3000]}
```

## 参考资源
来源: {reference_source}

内容:
{reference_content[:4000]}

{insert_hint}

## 任务
生成完整的代码借鉴建议，包含：

1. 一个简洁的标题
2. 详细的功能描述
3. 可直接插入的代码片段（适配现有代码风格）
4. 规范的参考来源注释
5. 修改说明列表
6. 风险提示列表
7. 测试建议列表

请严格按照以下JSON格式返回：
{{
    "title": "建议标题",
    "description": "详细描述",
    "insert_position": {{"location": "函数末尾/类中/文件末尾", "hint": "插入位置说明"}},
    "code_snippet": "完整的代码，包含参考注释",
    "modification_notes": ["修改说明1", "修改说明2"],
    "risk_warnings": ["风险1", "风险2"],
    "test_suggestions": ["测试建议1", "测试建议2"]
}}

只返回JSON，不要其他内容。
"""
        
        response = self.chat_completion([
            {"role": "system", "content": "你是专业的代码顾问，擅长将开源代码和论文思路融入现有项目。只返回JSON。"},
            {"role": "user", "content": prompt}
        ])
        
        try:
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                result = json.loads(response[json_start:json_end])
                
                import uuid
                return CodeSuggestion(
                    suggestion_id=str(uuid.uuid4())[:8],
                    title=result.get('title', '代码优化建议'),
                    description=result.get('description', ''),
                    insert_position=result.get('insert_position', {}),
                    code_snippet=result.get('code_snippet', ''),
                    modification_notes=result.get('modification_notes', []),
                    risk_warnings=result.get('risk_warnings', []),
                    test_suggestions=result.get('test_suggestions', []),
                    source_reference=reference_source
                )
        except Exception as e:
            logger.error(f"解析LLM响应失败: {e}, 响应: {response[:200]}")
        
        # 返回默认建议
        return CodeSuggestion(
            suggestion_id="default",
            title="代码参考建议",
            description=f"基于 {reference_source} 的代码参考",
            code_snippet=f"# 参考来源: {reference_source}\n# 请手动实现相关功能",
            source_reference=reference_source
        )
    
    def generate_analysis_report(self, project_analysis: Dict) -> str:
        """生成项目分析报告"""
        prompt = f"""
基于以下项目分析数据，生成一份专业的项目深度分析报告。

项目分析数据:
{json.dumps(project_analysis, ensure_ascii=False, indent=2)}

报告应包含：
1. 项目概览（规模、语言、结构）
2. 架构分析（模块划分、依赖关系）
3. 技术栈评估
4. 核心功能梳理
5. 改进建议

使用Markdown格式，专业、清晰、有深度。
"""
        
        report = self.chat_completion([
            {"role": "system", "content": "你是专业的软件架构师，擅长代码审计和项目分析。"},
            {"role": "user", "content": prompt}
        ])
        
        return report
    
    def generate_business_report(self, project_analysis, code_samples_text: str = "") -> str:
        """
        生成「给人看的」项目业务全景报告
        使用 BusinessAnalyzer 多阶段管线：先扫描 → 逐层发现业务概念 → 自评估 → 自改进 → 输出
        
        与旧版的区别：
        1. 通用性 —— 不硬编码特定项目知识，对任意代码库动态发现业务概念
        2. 自学习 —— 发现不足后自动优化分析方案再跑一遍
        3. 多层级 —— 技术架构 → 业务能力 → 用户角色 → 业务流程 → 跨端差异
        """
        try:
            from core.business_analyzer import BusinessAnalyzer
            
            analyzer = BusinessAnalyzer(llm_client=self)
            result = analyzer.analyze(project_analysis, max_iterations=3)
            report = analyzer.to_business_report(result)
            
            logger.info(f"[BusinessReport] 业务分析完成, 迭代{result.iteration_count}轮, "
                       f"得分{result.evaluation_scores[-1]:.0%}" if result.evaluation_scores else "")
            return report
            
        except Exception as e:
            logger.warning(f"[BusinessReport] BusinessAnalyzer 执行失败, 回退到旧版: {e}")
            # 回退：使用旧版方式
            return self._legacy_business_report(project_analysis, code_samples_text)
    
    def _legacy_business_report(self, project_analysis, code_samples_text: str = "") -> str:
        """（回退）旧版业务报告生成"""
        name = project_analysis.get("project_path", "").split("\\")[-1].split("/")[-1]
        total_files = project_analysis.get("total_files", 0)
        total_lines = project_analysis.get("total_lines", 0)
        languages = project_analysis.get("languages", {})
        modules_dict = project_analysis.get("modules", {})
        
        lang_str = ', '.join(f'{k}({v}文件)' for k, v in sorted(languages.items(), key=lambda x: -x[1]))
        mod_summary = []
        top_modules = {}
        for mod_path, files in modules_dict.items():
            top = mod_path.split('\\')[0].split('/')[0]
            if top not in top_modules:
                top_modules[top] = {'files': set()}
            top_modules[top]['files'].update(files)
        for mod, data in sorted(top_modules.items(), key=lambda x: -len(x[1]['files'])):
            mod_summary.append(f'- **{mod}**: {len(data["files"])}个文件')
        
        code_preview = code_samples_text[:40000] if code_samples_text else "（无代码数据）"
        
        prompt = f"""你是一位**业务架构师**。请分析以下代码项目，撰写一份**业务全景分析报告**。

【目标读者】非程序员（业务人员 / 管理者）
【要求】用通俗语言描述，不出现技术实现细节

## 项目数据
- 名称: {name}
- 文件数: {total_files}
- 代码行数: {total_lines:,}
- 语言: {lang_str}

## 模块分布
{chr(10).join(mod_summary[:10])}

## 代码样本
```
{code_preview}
```

请按以下结构输出 Markdown 报告：

### 一、项目定位 — 这个项目是做什么的（一句话）

### 二、业务模块全景 — 哪些子系统各自负责什么

### 三、用户角色 — 谁会使用这个系统，各角色能做什么

### 四、核心业务流程 — 关键操作步骤

### 五、差异对比 — Web端/桌面端差异、不同角色差异（如存在）

### 六、关键结论"""
        
        report = self.chat_completion([
            {"role": "system", "content": "你是一位擅长从代码中提取业务概念的业务架构师，能用通俗语言向非程序员解释代码架构。只输出 Markdown 报告。"},
            {"role": "user", "content": prompt}
        ])
        
        return report
    
    def extract_reference_points(self, resource_content: str) -> List[Dict[str, str]]:
        """从资源中提取可借鉴点"""
        prompt = f"""
从以下参考资源中，提取最有价值的、可以借鉴到其他项目中的核心要点。

资源内容:
{resource_content[:5000]}

请以JSON数组格式返回，每个元素包含：
- "title": 借鉴点标题
- "description": 详细说明
- "category": 分类（算法/架构/工具/最佳实践等）
- "priority": 优先级（high/medium/low）

只返回JSON数组。
"""
        
        response = self.chat_completion([
            {"role": "system", "content": "你是技术研究员，擅长从论文和开源项目中提取精华。只返回JSON。"},
            {"role": "user", "content": prompt}
        ])
        
        try:
            json_start = response.find('[')
            json_end = response.rfind(']') + 1
            if json_start >= 0 and json_end > json_start:
                return json.loads(response[json_start:json_end])
        except (json.JSONDecodeError, KeyError, ValueError):
            pass
        
        return []
