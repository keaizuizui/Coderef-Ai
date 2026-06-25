# -*- coding: utf-8 -*-
"""
代码知识库 —— 基于 Ollama Embedding 的代码向量化检索

核心能力：
1. 将代码块（函数/类/模块）向量化存储
2. 语义检索：根据自然语言查询找到最相关的代码
3. 相似代码检测：找到语义相似的代码片段
4. 调用链查询：从知识库中追踪函数调用关系

技术栈：
- Ollama + jina-embeddings-v2-base-zh (768维)
- SQLite 存储元数据
- numpy 做向量相似度计算（零外部依赖的回退方案）

设计原则：
- 通用化：不依赖任何特定项目
- 可离线：Ollama 本地运行，无需网络
- 可回退：Ollama 不可用时，自动降级为关键词匹配

作者: CodeRef-AI Team
版本: v2.0
"""

import json
import os
import re
import time
import sqlite3
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

import numpy as np
from loguru import logger

# 尝试导入 requests（用于 Ollama API）
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False


# ═══════════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════════

@dataclass
class CodeChunk:
    """代码块（知识库的最小单元）"""
    chunk_id: str           # 唯一标识（hash）
    file_path: str          # 文件路径
    chunk_type: str         # function / class / method / module / assignment
    name: str               # 函数名/类名/变量名
    code: str               # 完整代码
    start_line: int
    end_line: int
    docstring: str = ""     # 文档字符串
    parent: str = ""        # 所属类/模块
    embedding: Optional[np.ndarray] = None  # 向量（768维）
    metadata: Dict = field(default_factory=dict)  # 额外元数据

    def __hash__(self):
        return hash(self.chunk_id)


@dataclass
class SearchResult:
    """检索结果"""
    chunk: CodeChunk
    score: float            # 相似度分数 (0-1)
    rank: int               # 排名


# ═══════════════════════════════════════════════════════════════════
# Ollama Embedding 客户端
# ═══════════════════════════════════════════════════════════════════

class OllamaEmbedder:
    """
    Ollama Embedding 客户端

    使用 jina-embeddings-v2-base-zh 模型生成 768 维向量
    """

    DEFAULT_BASE_URL = "http://localhost:11434"
    DEFAULT_MODEL = "jina-embeddings-v2-base-zh"
    EMBEDDING_DIM = 768

    def __init__(self, base_url: str = None, model: str = None):
        self.base_url = base_url or os.environ.get("OLLAMA_BASE_URL", self.DEFAULT_BASE_URL)
        self.model = model or os.environ.get("OLLAMA_EMBED_MODEL", self.DEFAULT_MODEL)
        self._available = None
        self._checked = False

    def is_available(self) -> bool:
        """检查 Ollama 是否可用"""
        if self._checked:
            return self._available

        if not HAS_REQUESTS:
            logger.warning("[OllamaEmbedder] requests 未安装，无法使用 Ollama API")
            self._available = False
            self._checked = True
            return False

        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
            if resp.status_code == 200:
                models = resp.json().get("models", [])
                model_names = [m.get("name", "") for m in models]
                # 检查模型是否已安装
                if any(self.model in name for name in model_names):
                    self._available = True
                    logger.info(f"[OllamaEmbedder] Ollama 可用，模型: {self.model}")
                else:
                    logger.warning(f"[OllamaEmbedder] 模型 {self.model} 未安装，可用: {model_names}")
                    self._available = False
            else:
                self._available = False
        except Exception as e:
            logger.warning(f"[OllamaEmbedder] Ollama 连接失败: {e}")
            self._available = False

        self._checked = True
        return self._available

    def embed(self, text: str) -> Optional[np.ndarray]:
        """将文本向量化"""
        if not self.is_available():
            return None

        try:
            resp = requests.post(
                f"{self.base_url}/api/embeddings",
                json={"model": self.model, "prompt": text},
                timeout=30,
            )
            if resp.status_code == 200:
                embedding = resp.json().get("embedding", [])
                if len(embedding) == self.EMBEDDING_DIM:
                    return np.array(embedding, dtype=np.float32)
                else:
                    logger.warning(f"[OllamaEmbedder] 向量维度不匹配: {len(embedding)} != {self.EMBEDDING_DIM}")
            else:
                logger.warning(f"[OllamaEmbedder] API 错误: {resp.status_code}")
        except Exception as e:
            logger.warning(f"[OllamaEmbedder] 向量化失败: {e}")

        return None

    def embed_batch(self, texts: List[str], batch_size: int = 10) -> List[Optional[np.ndarray]]:
        """批量向量化"""
        results = []
        for i in range(0, len(texts), batch_size):
            batch = texts[i:i + batch_size]
            for text in batch:
                emb = self.embed(text)
                results.append(emb)
                time.sleep(0.05)  # 避免 Ollama 过载
        return results


# ═══════════════════════════════════════════════════════════════════
# 代码知识库
# ═══════════════════════════════════════════════════════════════════

class CodeKnowledgeBase:
    """
    代码知识库

    用法:
        kb = CodeKnowledgeBase("path/to/kb.db")
        kb.index_project("path/to/project")  # 索引项目
        results = kb.search("API Key 验证逻辑")  # 语义检索
        similar = kb.find_similar(chunk_id)  # 找相似代码
    """

    def __init__(self, db_path: str = "code_knowledge.db"):
        self.db_path = db_path
        self.embedder = OllamaEmbedder()
        self.chunks: Dict[str, CodeChunk] = {}
        self._init_db()

    def _init_db(self):
        """初始化数据库"""
        import json as _json

        @staticmethod
        def _safe_json_loads(s):
            try:
                return _json.loads(s)
            except (_json.JSONDecodeError, TypeError):
                return {}

        self._safe_json_loads = _safe_json_loads

        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS chunks (
                chunk_id TEXT PRIMARY KEY,
                file_path TEXT,
                chunk_type TEXT,
                name TEXT,
                code TEXT,
                start_line INTEGER,
                end_line INTEGER,
                docstring TEXT,
                parent TEXT,
                embedding BLOB,
                metadata TEXT
            )
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_chunks_file ON chunks(file_path)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_chunks_type ON chunks(chunk_type)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_chunks_name ON chunks(name)")
        conn.commit()
        conn.close()

    # ─── 索引 ──────────────────────────────────────────────────────

    def index_project(self, project_path: str, max_files: int = 5000) -> int:
        """
        索引整个项目

        使用 AST 解析所有 Python 文件，将每个函数/类/方法作为代码块存储
        """
        from core.ast_parser import AstProjectParser, AstParser

        logger.info(f"[CodeKB] 开始索引项目: {project_path}")

        # 解析项目
        parser = AstProjectParser(project_path)
        ast_results = parser.parse_all(max_files=max_files)

        # 创建代码块
        chunks = []
        for file_path, result in ast_results.items():
            # 模块级 docstring
            if result.module_docstring:
                chunks.append(CodeChunk(
                    chunk_id=self._make_id(file_path, "module", "__doc__"),
                    file_path=file_path,
                    chunk_type="module",
                    name=os.path.basename(file_path),
                    code=result.module_docstring,
                    start_line=1,
                    end_line=1,
                    docstring=result.module_docstring,
                ))

            # 顶层函数
            for func in result.functions:
                chunks.append(CodeChunk(
                    chunk_id=self._make_id(file_path, "function", func.name),
                    file_path=file_path,
                    chunk_type="function",
                    name=func.name,
                    code=func.code or "",
                    start_line=func.start_line,
                    end_line=func.end_line,
                    docstring=func.docstring or "",
                    metadata={
                        "parameters": func.parameters,
                        "return_type": func.return_type,
                        "decorators": func.decorators,
                        "is_async": func.is_async,
                    },
                ))

            # 类和方法
            for cls in result.classes:
                # 类本身
                cls_code = self._extract_class_code(cls, result)
                chunks.append(CodeChunk(
                    chunk_id=self._make_id(file_path, "class", cls.name),
                    file_path=file_path,
                    chunk_type="class",
                    name=cls.name,
                    code=cls_code,
                    start_line=cls.start_line,
                    end_line=cls.end_line,
                    docstring=cls.docstring or "",
                    metadata={"base_classes": cls.base_classes},
                ))

                # 方法
                for method in cls.methods:
                    chunks.append(CodeChunk(
                        chunk_id=self._make_id(file_path, "method", f"{cls.name}.{method.name}"),
                        file_path=file_path,
                        chunk_type="method",
                        name=f"{cls.name}.{method.name}",
                        code=method.code or "",
                        start_line=method.start_line,
                        end_line=method.end_line,
                        docstring=method.docstring or "",
                        parent=cls.name,
                        metadata={
                            "parameters": method.parameters,
                            "return_type": method.return_type,
                            "decorators": method.decorators,
                            "is_async": method.is_async,
                        },
                    ))

            # 赋值语句（只保留被分类为 hardcoded 或 config 的）
            for assign in result.assignments:
                if assign.category in ("hardcoded", "config"):
                    chunks.append(CodeChunk(
                        chunk_id=self._make_id(file_path, "assignment", assign.target),
                        file_path=file_path,
                        chunk_type="assignment",
                        name=assign.target,
                        code=f"{assign.target} = {assign.value_repr}",
                        start_line=assign.line,
                        end_line=assign.line,
                        metadata={"category": assign.category, "value": assign.value_repr},
                    ))

        logger.info(f"[CodeKB] 创建了 {len(chunks)} 个代码块")

        # 向量化（如果 Ollama 可用）
        use_embedding = self.embedder.is_available()
        if use_embedding:
            logger.info("[CodeKB] 使用 Ollama 向量化...")
            texts = [self._chunk_to_text(c) for c in chunks]
            embeddings = self.embedder.embed_batch(texts, batch_size=10)
            for chunk, emb in zip(chunks, embeddings):
                chunk.embedding = emb
            embedded_count = sum(1 for e in embeddings if e is not None)
            logger.info(f"[CodeKB] 向量化完成: {embedded_count}/{len(chunks)}")
        else:
            logger.warning("[CodeKB] Ollama 不可用，跳过向量化，将使用关键词检索")

        # 存储
        self._store_chunks(chunks)
        self.chunks = {c.chunk_id: c for c in chunks}

        logger.info(f"[CodeKB] 索引完成: {len(chunks)} 个代码块")
        return len(chunks)

    def _store_chunks(self, chunks: List[CodeChunk]):
        """批量存储代码块"""
        conn = sqlite3.connect(self.db_path)
        data = []
        for c in chunks:
            emb_blob = None
            if c.embedding is not None:
                emb_blob = c.embedding.tobytes()
            data.append((
                c.chunk_id, c.file_path, c.chunk_type, c.name,
                c.code, c.start_line, c.end_line,
                c.docstring, c.parent, emb_blob,
                json.dumps(c.metadata, ensure_ascii=False),
            ))
        conn.executemany(
            "INSERT OR REPLACE INTO chunks VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            data,
        )
        conn.commit()
        conn.close()

    def _load_chunks(self):
        """从数据库加载代码块"""
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("SELECT * FROM chunks").fetchall()
        conn.close()

        self.chunks = {}
        for row in rows:
            chunk_id, file_path, chunk_type, name, code, start_line, end_line, \
                docstring, parent, emb_blob, metadata_str = row

            embedding = None
            if emb_blob:
                embedding = np.frombuffer(emb_blob, dtype=np.float32)

            self.chunks[chunk_id] = CodeChunk(
                chunk_id=chunk_id,
                file_path=file_path,
                chunk_type=chunk_type,
                name=name,
                code=code,
                start_line=start_line,
                end_line=end_line,
                docstring=docstring,
                parent=parent,
                embedding=embedding,
                metadata=self._safe_json_loads(metadata_str) if metadata_str else {},
            )

    # ─── 检索 ──────────────────────────────────────────────────────

    def search(self, query: str, top_k: int = 10,
               chunk_type: str = None) -> List[SearchResult]:
        """
        语义检索代码块

        优先使用向量相似度，Ollama 不可用时降级为关键词匹配
        """
        if not self.chunks:
            self._load_chunks()

        query_embedding = self.embedder.embed(query) if self.embedder.is_available() else None

        if query_embedding is not None and any(c.embedding is not None for c in self.chunks.values()):
            # 向量检索
            return self._vector_search(query_embedding, top_k, chunk_type)
        else:
            # 关键词检索（降级）
            return self._keyword_search(query, top_k, chunk_type)

    def _vector_search(self, query_emb: np.ndarray, top_k: int,
                       chunk_type: str = None) -> List[SearchResult]:
        """向量相似度检索"""
        scores = []
        for chunk in self.chunks.values():
            if chunk_type and chunk.chunk_type != chunk_type:
                continue
            if chunk.embedding is None:
                continue
            # 余弦相似度
            score = np.dot(query_emb, chunk.embedding) / (
                np.linalg.norm(query_emb) * np.linalg.norm(chunk.embedding) + 1e-8
            )
            scores.append((chunk, float(score)))

        scores.sort(key=lambda x: x[1], reverse=True)
        return [
            SearchResult(chunk=c, score=s, rank=i + 1)
            for i, (c, s) in enumerate(scores[:top_k])
        ]

    def _keyword_search(self, query: str, top_k: int,
                        chunk_type: str = None) -> List[SearchResult]:
        """关键词匹配检索（降级方案）"""
        keywords = set(re.findall(r'[\w\u4e00-\u9fff]+', query.lower()))
        scores = []

        for chunk in self.chunks.values():
            if chunk_type and chunk.chunk_type != chunk_type:
                continue
            text = self._chunk_to_text(chunk).lower()
            # 计算关键词命中率
            hits = sum(1 for kw in keywords if kw in text)
            if hits > 0:
                score = hits / len(keywords)
                scores.append((chunk, score))

        scores.sort(key=lambda x: x[1], reverse=True)
        return [
            SearchResult(chunk=c, score=s, rank=i + 1)
            for i, (c, s) in enumerate(scores[:top_k])
        ]

    def find_similar(self, chunk_id: str, top_k: int = 5) -> List[SearchResult]:
        """找到与指定代码块相似的代码"""
        if not self.chunks:
            self._load_chunks()

        target = self.chunks.get(chunk_id)
        if not target or target.embedding is None:
            return []

        return self._vector_search(target.embedding, top_k + 1)[1:]  # 排除自己

    def search_by_file(self, file_path: str) -> List[CodeChunk]:
        """按文件路径检索"""
        if not self.chunks:
            self._load_chunks()
        return [c for c in self.chunks.values() if file_path in c.file_path]

    def get_calls_to(self, func_name: str) -> List[CodeChunk]:
        """查找调用指定函数的代码块"""
        if not self.chunks:
            self._load_chunks()

        results = []
        for chunk in self.chunks.values():
            if func_name in chunk.code:
                # 简单检查：函数名后面跟着 (
                pattern = re.compile(r'\b' + re.escape(func_name) + r'\s*\(')
                if pattern.search(chunk.code):
                    results.append(chunk)
        return results

    # ─── 统计 ──────────────────────────────────────────────────────

    def stats(self) -> Dict:
        """获取知识库统计信息"""
        if not self.chunks:
            self._load_chunks()

        type_counts = {}
        file_counts = {}
        for c in self.chunks.values():
            type_counts[c.chunk_type] = type_counts.get(c.chunk_type, 0) + 1
            file_counts[c.file_path] = file_counts.get(c.file_path, 0) + 1

        has_embeddings = sum(1 for c in self.chunks.values() if c.embedding is not None)

        return {
            "total_chunks": len(self.chunks),
            "total_files": len(file_counts),
            "has_embeddings": has_embeddings,
            "embedding_ratio": f"{has_embeddings}/{len(self.chunks)}",
            "by_type": type_counts,
            "ollama_available": self.embedder.is_available(),
        }

    # ─── 辅助 ──────────────────────────────────────────────────────

    def _chunk_to_text(self, chunk: CodeChunk) -> str:
        """将代码块转为可向量化的文本"""
        parts = [f"{chunk.chunk_type}: {chunk.name}"]
        if chunk.docstring:
            parts.append(chunk.docstring)
        # 只取代码的前 500 字符用于向量化（避免过长）
        code_preview = chunk.code[:500]
        if len(chunk.code) > 500:
            code_preview += "..."
        parts.append(code_preview)
        return "\n".join(parts)

    def _extract_class_code(self, cls, ast_result) -> str:
        """提取类代码（从 AST 结果中获取）"""
        # 从文件内容中提取类代码
        if hasattr(cls, 'code') and cls.code:
            return cls.code
        return f"class {cls.name}({', '.join(cls.base_classes)}): ..."

    def _make_id(self, file_path: str, chunk_type: str, name: str) -> str:
        """生成唯一 ID"""
        raw = f"{file_path}:{chunk_type}:{name}"
        return hashlib.md5(raw.encode()).hexdigest()[:16]


# ═══════════════════════════════════════════════════════════════════
# LLM 分析器（基于知识库）
# ═══════════════════════════════════════════════════════════════════

class LLMAnalyzer:
    """
    基于知识库的 LLM 代码分析器

    用法:
        analyzer = LLMAnalyzer(kb)
        issues = analyzer.audit_security()    # 安全审计
        modules = analyzer.discover_modules()  # 模块发现
        workflows = analyzer.extract_workflows()  # 业务流程提取
    """

    def __init__(self, kb: CodeKnowledgeBase, llm_client=None):
        self.kb = kb
        self.llm = llm_client

    def _call_llm(self, prompt: str) -> Optional[str]:
        """调用 LLM（如果可用）"""
        if self.llm and hasattr(self.llm, 'chat_completion'):
            try:
                return self.llm.chat_completion([
                    {"role": "system", "content": "你是一个代码分析专家。请分析代码并返回JSON格式结果。"},
                    {"role": "user", "content": prompt},
                ])
            except Exception as e:
                logger.warning(f"[LLMAnalyzer] LLM 调用失败: {e}")
        return None

    def analyze_security(self, top_k: int = 20) -> List[Dict]:
        """
        安全审计：检索可疑代码块，用 LLM 做语义判断

        替代了过去硬编码正则的方式：
        - 旧方式：api_key = "xxx" 正则匹配 → 误报 E1001_KEY = "E1001_KEY"
        - 新方式：检索赋值语句 → LLM 判断是否真的是硬编码凭据
        """
        # 检索所有硬编码赋值
        results = self.kb.search("password secret token api_key 硬编码", top_k=50, chunk_type="assignment")

        # 如果 LLM 可用，用 LLM 做语义判断
        if self._call_llm:
            findings = []
            for r in results[:top_k]:
                prompt = f"""判断以下代码是否是硬编码的敏感凭据（密码、Token、API Key等）：

代码: {r.chunk.code}
文件: {r.chunk.file_path}
行号: {r.chunk.start_line}

请以 JSON 格式返回：
{{"is_secret": true/false, "reason": "判断理由", "severity": "critical/high/medium/low/safe"}}

如果是错误码常量定义（如 E1001_KEY = "E1001_KEY"）、配置读取（如 os.environ.get()）、或输入验证规则，则 is_secret 应为 false。
"""
                llm_result = self._call_llm(prompt)
                if llm_result:
                    try:
                        # 提取 JSON
                        json_match = re.search(r'\{[^}]+\}', llm_result)
                        if json_match:
                            decision = json.loads(json_match.group())
                            if decision.get("is_secret"):
                                findings.append({
                                    "file": r.chunk.file_path,
                                    "line": r.chunk.start_line,
                                    "code": r.chunk.code,
                                    "reason": decision.get("reason", ""),
                                    "severity": decision.get("severity", "high"),
                                })
                    except json.JSONDecodeError:
                        pass

            return findings

        # 降级：只返回关键词检索结果，标注为"待确认"
        return [
            {
                "file": r.chunk.file_path,
                "line": r.chunk.start_line,
                "code": r.chunk.code,
                "reason": "关键词匹配（待 LLM 确认）",
                "severity": "medium",
                "needs_review": True,
            }
            for r in results[:top_k]
        ]

    def discover_modules(self) -> List[Dict]:
        """
        模块发现：通过检索聚类发现项目模块

        替代了过去硬编码目录名的方式。
        """
        # 检索模块级代码块
        modules = self.kb.search("模块 入口 main 初始化", top_k=20, chunk_type="module")

        # 用 LLM 分析模块职责
        if self._call_llm:
            module_texts = []
            for r in modules:
                module_texts.append(f"文件: {r.chunk.file_path}\n描述: {r.chunk.docstring}\n")

            prompt = f"""分析以下项目模块，识别每个模块的职责和业务定位：

{chr(10).join(module_texts[:15])}

返回 JSON 格式：
[{{"name": "模块名", "path": "路径", "responsibility": "职责描述", "category": "入口/核心/数据/共享/基础设施"}}]
"""
            llm_result = self._call_llm(prompt)
            if llm_result:
                try:
                    json_match = re.search(r'\[.*\]', llm_result, re.DOTALL)
                    if json_match:
                        return json.loads(json_match.group())
                except json.JSONDecodeError:
                    pass

        # 降级：按目录分组
        dir_modules = {}
        for r in modules:
            dir_name = os.path.basename(os.path.dirname(r.chunk.file_path))
            if dir_name not in dir_modules:
                dir_modules[dir_name] = []
            dir_modules[dir_name].append(r.chunk.file_path)

        return [
            {"name": dir_name, "path": dir_name, "responsibility": "", "category": "other"}
            for dir_name in dir_modules
        ]

    def extract_workflows(self) -> List[Dict]:
        """
        提取业务流程：从调用链中重建端到端工作流

        这是 CodeRef 最核心的升级 —— 从"未识别到业务流程"到自动提取。
        """
        # 检索入口函数
        entries = self.kb.search("main run start execute 入口 启动", top_k=10, chunk_type="function")

        if not entries:
            return []

        # 用 LLM 追踪调用链
        if self._call_llm:
            entry_texts = []
            for e in entries[:5]:
                # 找到被该函数调用的代码
                callees = self.kb.search(e.chunk.name, top_k=5, chunk_type="function")
                callee_texts = []
                for c in callees:
                    if c.chunk.name != e.chunk.name:
                        callee_texts.append(f"  → {c.chunk.name}: {c.chunk.docstring[:100]}")

                entry_texts.append(
                    f"入口: {e.chunk.name} ({e.chunk.file_path})\n"
                    f"描述: {e.chunk.docstring[:200]}\n"
                    f"调用: {chr(10).join(callee_texts[:5])}\n"
                )

            prompt = f"""分析以下代码入口点，提取端到端的业务流程：

{chr(10).join(entry_texts)}

返回 JSON 格式：
[{{"name": "流程名", "steps": ["步骤1", "步骤2", ...], "entry": "入口函数", "description": "流程描述"}}]
"""
            llm_result = self._call_llm(prompt)
            if llm_result:
                try:
                    json_match = re.search(r'\[.*\]', llm_result, re.DOTALL)
                    if json_match:
                        return json.loads(json_match.group())
                except json.JSONDecodeError:
                    pass

        # 降级：返回入口函数列表
        return [
            {
                "name": e.chunk.name,
                "steps": [e.chunk.docstring or "未解析"],
                "entry": e.chunk.file_path,
                "description": "基于函数名和 docstring（待 LLM 增强）",
            }
            for e in entries[:5]
        ]


# ═══════════════════════════════════════════════════════════════════
# CLI 工具
# ═══════════════════════════════════════════════════════════════════

def build_knowledge_base(project_path: str, db_path: str = None) -> CodeKnowledgeBase:
    """一键构建知识库"""
    if db_path is None:
        project_name = os.path.basename(os.path.abspath(project_path))
        db_path = os.path.join(project_path, f".code_knowledge_{project_name}.db")

    kb = CodeKnowledgeBase(db_path)
    count = kb.index_project(project_path)
    stats = kb.stats()
    logger.info(f"[CodeKB] 构建完成: {stats}")
    return kb
