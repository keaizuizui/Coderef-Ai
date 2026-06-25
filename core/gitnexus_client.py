"""
GitNexus MCP Client —— 通过MCP协议(JSON-RPC over stdio)连接GitNexus

GitNexus MCP Server 暴露以下工具：
- list_repos: 列出所有已索引的仓库
- query: 混合BM25+向量搜索
- context: 获取符号的调用者/被调用者/所属进程
- impact: 爆炸半径分析（上游/下游+风险摘要）
- detect_changes: Git diff影响分析
- rename: 多文件协调重命名
- cypher: 自定义Cypher图查询

通信方式：
  启动 `gitnexus mcp` 子进程 → 通过 stdin/stdout 发送 JSON-RPC 2.0 请求
"""

import json
import os
import subprocess
import logging
import threading
import time
from typing import Optional, Dict, List, Any
from dataclasses import dataclass, field
from queue import Queue, Empty

logger = logging.getLogger(__name__)


@dataclass
class GraphNode:
    """图谱节点"""
    id: str
    name: str
    qualified_name: str = ""
    file_path: str = ""
    node_type: str = ""  # Function/Class/Module/File等
    language: str = ""
    start_line: int = 0
    end_line: int = 0
    community: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    """图谱边"""
    source: str
    target: str
    relation_type: str = ""  # CALLS/IMPORTS/EXTENDS/HANDLES_ROUTE等
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class Subgraph:
    """子图——包含节点、边和入口点"""
    entry_point: str
    nodes: List[GraphNode] = field(default_factory=list)
    edges: List[GraphEdge] = field(default_factory=list)
    upstream: List[str] = field(default_factory=list)  # 上游节点ID/名称
    downstream: List[str] = field(default_factory=list)  # 下游节点ID/名称
    processes: List[Dict] = field(default_factory=list)  # 所属进程
    risk_summary: str = ""
    raw_context: Dict = field(default_factory=dict)
    raw_impact: Dict = field(default_factory=dict)


@dataclass
class GitNexusEnrichment:
    """GitNexus 增强数据 —— 供 BusinessAnalyzer 管线使用
    
    整合 GitNexus 的符号索引 + 调用图数据，注入业务分析管线。
    """
    available: bool = False                     # GitNexus 是否可用
    repo_name: str = ""                         # 匹配到的仓库名
    all_symbols: List[Dict] = field(default_factory=list)       # [{name, filePath, type, ...}]
    file_symbols: Dict[str, List[Dict]] = field(default_factory=dict)  # filePath → [symbols...]
    call_pairs: List[tuple] = field(default_factory=list)        # [(caller, callee)]
    caller_index: Dict[str, List[str]] = field(default_factory=dict)   # callee → [callers]
    callee_index: Dict[str, List[str]] = field(default_factory=dict)   # caller → [callees]
    search_results: Dict[str, List[Dict]] = field(default_factory=dict) # keyword → [results]
    entry_points: List[str] = field(default_factory=list)         # 发现的关键入口函数
    error: str = ""


class GitNexusMCPClient:
    """通过MCP协议(JSON-RPC over stdio)连接GitNexus的客户端

    使用方式：
    1. 确保已安装GitNexus: npm install -g gitnexus
    2. 确保已索引目标项目: cd /path/to/project && gitnexus analyze
    3. 使用本客户端连接（自动启动 gitnexus mcp 子进程）

    生命周期管理：
    - 使用 with 语句自动管理进程生命周期
    - 或手动调用 start() / stop()
    """

    def __init__(self, project_path: Optional[str] = None):
        """
        Args:
            project_path: 目标项目路径（用于定位.gitnexus目录）
        """
        self.project_path = project_path
        self._process: Optional[subprocess.Popen] = None
        self._request_id = 0
        self._lock = threading.Lock()
        self._response_queue: Queue = Queue()
        self._reader_thread: Optional[threading.Thread] = None
        self._initialized = False
        self._server_capabilities: Dict = {}

    def _next_id(self) -> int:
        with self._lock:
            self._request_id += 1
            return self._request_id

    def _send_request(self, method: str, params: Optional[Dict] = None) -> Dict:
        """发送JSON-RPC请求并等待响应"""
        if not self._process or self._process.poll() is not None:
            raise ConnectionError("GitNexus MCP进程未运行，请先调用 start()")

        request_id = self._next_id()
        request = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": method,
        }
        if params:
            request["params"] = params

        request_str = json.dumps(request)

        try:
            self._process.stdin.write(request_str + "\n")
            self._process.stdin.flush()
        except (BrokenPipeError, OSError) as e:
            raise ConnectionError(f"写入MCP进程失败: {e}")

        # 等待对应ID的响应（超时60秒）
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                msg = self._response_queue.get(timeout=2)
                if msg.get("id") == request_id:
                    if "error" in msg:
                        raise RuntimeError(
                            f"MCP错误 {msg['error'].get('code')}: "
                            f"{msg['error'].get('message')}"
                        )
                    return msg.get("result", {})
            except Empty:
                continue

        raise TimeoutError(f"MCP请求超时: {method}")

    def _reader_loop(self):
        """后台线程：持续读取MCP进程的stdout"""
        try:
            buffer = ""
            while self._process and self._process.poll() is None:
                chunk = self._process.stdout.read(1)
                if not chunk:
                    break
                buffer += chunk
                # JSON-RPC消息以换行分隔
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if line:
                        try:
                            msg = json.loads(line)
                            self._response_queue.put(msg)
                        except json.JSONDecodeError:
                            # 忽略非JSON行（如日志输出）
                            pass
        except Exception as e:
            logger.debug(f"[GitNexus] Reader线程退出: {e}")
        finally:
            self._response_queue.put(None)  # 信号：读取结束

    def start(self):
        """启动GitNexus MCP子进程"""
        if self._process and self._process.poll() is None:
            return  # 已在运行

        try:
            # V2.0: 设置 cwd 为 project_path，让 gitnexus mcp 在正确的项目目录下启动
            # 这样才能找到 .gitnexus/ 索引数据
            cwd = self.project_path if self.project_path else None
            # V2.1: 使用 npx -y gitnexus mcp，因为 gitnexus 通常通过 npx 运行而非全局安装
            cmd = "npx -y gitnexus mcp"
            self._process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                bufsize=1,  # 行缓冲
                shell=True,
                cwd=cwd,
            )
        except FileNotFoundError:
            raise RuntimeError(
                "gitnexus CLI未找到。请先安装: npm install -g gitnexus"
            )

        # 启动后台读取线程
        self._response_queue = Queue()
        self._reader_thread = threading.Thread(
            target=self._reader_loop, daemon=True
        )
        self._reader_thread.start()

        # 发送 initialize 握手
        init_result = self._send_request("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {
                "name": "coderef-ai",
                "version": "2.0.0"
            }
        })
        self._server_capabilities = init_result.get("capabilities", {})

        # 发送 initialized 通知
        self._send_notification("notifications/initialized")
        self._initialized = True
        logger.info("[GitNexus] MCP连接已建立")

    def _send_notification(self, method: str, params: Optional[Dict] = None):
        """发送JSON-RPC通知（不需要响应）"""
        if not self._process or self._process.poll() is not None:
            return
        notification = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params:
            notification["params"] = params
        try:
            self._process.stdin.write(json.dumps(notification) + "\n")
            self._process.stdin.flush()
        except (BrokenPipeError, OSError):
            pass

    def stop(self):
        """停止GitNexus MCP子进程"""
        if self._process:
            try:
                self._process.stdin.close()
            except Exception:
                pass
            try:
                self._process.terminate()
                self._process.wait(timeout=5)
            except Exception:
                try:
                    self._process.kill()
                except Exception:
                    pass
            self._process = None
        self._initialized = False
        logger.info("[GitNexus] MCP连接已关闭")

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()

    def _call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        """通过MCP协议调用GitNexus工具"""
        if not self._initialized:
            self.start()

        result = self._send_request("tools/call", {
            "name": tool_name,
            "arguments": arguments
        })

        # MCP工具返回格式: {"content": [{"type": "text", "text": "..."}]}
        content = result.get("content", [])
        for item in content:
            if item.get("type") == "text":
                text = item.get("text", "")
                # V2.1: gitnexus 返回 JSON + Markdown 后缀（\n\n---\n**Next:**...）
                # 策略：找到第一个 { 或 [，平衡括号提取完整 JSON
                for start_char, end_char in [('{', '}'), ('[', ']')]:
                    start_idx = text.find(start_char)
                    if start_idx == -1:
                        continue
                    depth = 0
                    in_string = False
                    escape_next = False
                    for i, c in enumerate(text[start_idx:], start_idx):
                        if escape_next:
                            escape_next = False
                            continue
                        if c == '\\':
                            escape_next = True
                            continue
                        if c == '"':
                            in_string = not in_string
                            continue
                        if not in_string:
                            if c == start_char:
                                depth += 1
                            elif c == end_char:
                                depth -= 1
                                if depth == 0:
                                    try:
                                        return json.loads(text[start_idx:i+1])
                                    except (json.JSONDecodeError, TypeError):
                                        break
                    break
                return text
        return result

    # ==================== 公共API ====================

    def list_repos(self) -> List[Dict]:
        """列出所有已索引的仓库"""
        result = self._call_tool("list_repos", {})
        if isinstance(result, list):
            return result
        if isinstance(result, dict):
            return result.get("repos", result.get("repositories", []))
        return []

    def get_context(self, symbol: str, repo: Optional[str] = None) -> Dict:
        """获取符号的上下文（调用者/被调用者/所属进程）

        Args:
            symbol: 符号名（如 "createOrder" 或 "src/services/order.js:createOrder"）
            repo: 仓库名（可选，多仓库时需要）
        """
        args = {"name": symbol}  # V2.1: GitNexus API 使用 'name' 而非 'symbol'
        if repo:
            args["repo"] = repo
        result = self._call_tool("context", args)
        if isinstance(result, str):
            try:
                return json.loads(result)
            except json.JSONDecodeError:
                return {"raw_text": result}
        return result if isinstance(result, dict) else {}

    def get_impact(self, symbol: str, repo: Optional[str] = None) -> Dict:
        """获取符号的爆炸半径（上游/下游+风险摘要）

        Args:
            symbol: 符号名
            repo: 仓库名（可选）
        """
        args = {"target": symbol}  # V2.1: GitNexus API 使用 'target' 而非 'symbol'
        if repo:
            args["repo"] = repo
        result = self._call_tool("impact", args)
        if isinstance(result, str):
            try:
                return json.loads(result)
            except json.JSONDecodeError:
                return {"raw_text": result}
        return result if isinstance(result, dict) else {}

    def query_cypher(self, cypher: str, repo: Optional[str] = None) -> Any:
        """执行自定义Cypher查询

        Args:
            cypher: Cypher查询语句
            repo: 仓库名（可选）
        """
        args = {"query": cypher}
        if repo:
            args["repo"] = repo
        return self._call_tool("cypher", args)

    def search(self, query: str, repo: Optional[str] = None) -> Any:
        """混合搜索（BM25+向量+RRF）

        Args:
            query: 搜索关键词
            repo: 仓库名（可选）
        """
        args = {"query": query}
        if repo:
            args["repo"] = repo
        return self._call_tool("query", args)

    def detect_changes(self, repo: Optional[str] = None) -> Any:
        """Git diff影响分析

        Args:
            repo: 仓库名（可选）
        """
        args = {}
        if repo:
            args["repo"] = repo
        return self._call_tool("detect_changes", args)

    def extract_subgraph(self, entry: str, depth: int = 3) -> Subgraph:
        """提取以entry为中心的子图

        综合使用 context + impact + cypher 三种工具提取完整子图

        Args:
            entry: 入口点（符号名或 file:function 格式）
            depth: 上下游遍历深度（默认3）

        Returns:
            Subgraph 包含节点、边、上下游关系
        """
        subgraph = Subgraph(entry_point=entry)

        # 1. 获取上下文（调用者/被调用者/进程）
        try:
            context = self.get_context(entry)
            subgraph.raw_context = context if isinstance(context, dict) else {}

            if isinstance(context, dict):
                # 提取进程信息
                processes = context.get("processes", [])
                if isinstance(processes, list):
                    subgraph.processes = processes

                # V2.1: GitNexus 返回 incoming/outgoing 结构
                # incoming.imports = 调用此符号的上游
                # outgoing.calls = 此符号调用的下游
                incoming = context.get("incoming", {})
                outgoing = context.get("outgoing", {})

                # 从 incoming 的所有分类中提取上游
                if not subgraph.upstream:
                    for category in ["imports", "callers", "upstream", "references"]:
                        items = incoming.get(category, [])
                        if isinstance(items, list):
                            for c in items:
                                name = c.get("name", c) if isinstance(c, dict) else str(c)
                                if name and name not in subgraph.upstream:
                                    subgraph.upstream.append(name)

                # 从 outgoing 的所有分类中提取下游
                if not subgraph.downstream:
                    for category in ["calls", "callees", "downstream", "has_method"]:
                        items = outgoing.get(category, [])
                        if isinstance(items, list):
                            for c in items:
                                name = c.get("name", c) if isinstance(c, dict) else str(c)
                                if name and name not in subgraph.downstream:
                                    subgraph.downstream.append(name)

                # 兼容旧格式: callers/callees 顶层字段
                if not subgraph.upstream:
                    callers = context.get("callers", context.get("upstream", []))
                    if isinstance(callers, list):
                        subgraph.upstream = [
                            c.get("name", c) if isinstance(c, dict) else str(c)
                            for c in callers
                        ]
                if not subgraph.downstream:
                    callees = context.get("callees", context.get("downstream", []))
                    if isinstance(callees, list):
                        subgraph.downstream = [
                            c.get("name", c) if isinstance(c, dict) else str(c)
                            for c in callees
                        ]

                # 填充节点元数据
                sym = context.get("symbol")
                if isinstance(sym, dict):
                    for node in subgraph.nodes:
                        if node.name == entry:
                            node.qualified_name = sym.get("uid", "")
                            node.file_path = sym.get("filePath", "")
                            node.node_type = sym.get("kind", "")
                            node.start_line = sym.get("startLine", 0)
                            node.end_line = sym.get("endLine", 0)
                            break
        except Exception as e:
            logger.warning(f"[GitNexus] context查询失败: {e}")

        # 2. 获取爆炸半径（补充上下游+风险）
        try:
            impact = self.get_impact(entry)
            subgraph.raw_impact = impact if isinstance(impact, dict) else {}

            if isinstance(impact, dict):
                # V2.1: GitNexus 返回 risk 字段（非 risk_summary）
                risk = impact.get("risk_summary", impact.get("risk", ""))
                if risk:
                    subgraph.risk_summary = risk if isinstance(risk, str) else str(risk)

                # V2.1: 从 affected_processes 提取上下游
                if not subgraph.upstream or not subgraph.downstream:
                    affected = impact.get("affected_processes", [])
                    if isinstance(affected, list):
                        for proc in affected:
                            if isinstance(proc, dict):
                                name = proc.get("name", "")
                                fp = proc.get("filePath", "")
                                if name and name != entry:
                                    if name not in subgraph.downstream and name not in subgraph.upstream:
                                        subgraph.downstream.append(name)

                # 兼容旧格式
                if not subgraph.upstream:
                    upstream = impact.get("upstream", impact.get("callers", []))
                    if isinstance(upstream, list):
                        subgraph.upstream = [
                            u.get("name", u) if isinstance(u, dict) else str(u)
                            for u in upstream
                        ]
                if not subgraph.downstream:
                    downstream = impact.get("downstream", impact.get("callees", []))
                    if isinstance(downstream, list):
                        subgraph.downstream = [
                            d.get("name", d) if isinstance(d, dict) else str(d)
                            for d in downstream
                        ]
        except Exception as e:
            logger.warning(f"[GitNexus] impact查询失败: {e}")

        # 3. 构建节点和边
        all_names = set()
        all_names.add(entry)
        all_names.update(subgraph.upstream)
        all_names.update(subgraph.downstream)

        for name in all_names:
            subgraph.nodes.append(GraphNode(
                id=name,
                name=name,
            ))

        # 上游边
        for caller in subgraph.upstream:
            subgraph.edges.append(GraphEdge(
                source=caller,
                target=entry,
                relation_type="CALLS"
            ))

        # 下游边
        for callee in subgraph.downstream:
            subgraph.edges.append(GraphEdge(
                source=entry,
                target=callee,
                relation_type="CALLS"
            ))

        return subgraph

    def extract_subgraph_cypher(self, entry: str, depth: int = 3) -> Subgraph:
        """通过Cypher查询提取子图（备选方案）

        当context/impact工具返回不够详细时，可以用Cypher直接查图谱

        Args:
            entry: 入口点符号名
            depth: 遍历深度
        """
        subgraph = Subgraph(entry_point=entry)

        try:
            # 查询完整子图
            cypher = f"""
            MATCH path = (upstream)-[:CodeRelation*1..{depth}]->(entry {{name: '{entry}'}})-[:CodeRelation*1..{depth}]->(downstream)
            RETURN path
            """
            result = self.query_cypher(cypher)

            if isinstance(result, dict):
                # 解析Cypher结果
                nodes_data = result.get("nodes", result.get("data", []))
                edges_data = result.get("edges", result.get("relationships", []))

                if isinstance(nodes_data, list):
                    for n in nodes_data:
                        if isinstance(n, dict):
                            subgraph.nodes.append(GraphNode(
                                id=n.get("id", n.get("name", "")),
                                name=n.get("name", ""),
                                qualified_name=n.get("qualifiedName", n.get("qualified_name", "")),
                                file_path=n.get("filePath", n.get("file_path", "")),
                                node_type=n.get("type", n.get("nodeType", "")),
                                language=n.get("language", ""),
                            ))

                if isinstance(edges_data, list):
                    for e in edges_data:
                        if isinstance(e, dict):
                            subgraph.edges.append(GraphEdge(
                                source=e.get("source", e.get("from", "")),
                                target=e.get("target", e.get("to", "")),
                                relation_type=e.get("type", e.get("relationType", "CALLS")),
                            ))
        except Exception as e:
            logger.warning(f"[GitNexus] Cypher查询失败: {e}")

        return subgraph

    def get_schema(self, repo: Optional[str] = None) -> str:
        """获取图谱schema（用于编写Cypher查询）"""
        # 通过MCP资源获取schema
        args = {}
        if repo:
            args["repo"] = repo
        result = self._call_tool("cypher", {"query": "CALL schema()"})
        if isinstance(result, str):
            return result
        if isinstance(result, dict):
            return json.dumps(result, indent=2, ensure_ascii=False)
        return str(result)

    # ==================== 批量增强API（供 BusinessAnalyzer 管线使用） ====================

    def enrich_project(self, project_path: str, repo_name: str = "") -> 'GitNexusEnrichment':
        """
        一站式增强分析入口 —— 给 BusinessAnalyzer 管线调用
        
        策略：
        1. 查找匹配的仓库名
        2. 通过 Cypher 获取全项目符号 + 调用图
        3. 批量搜索业务关键词
        4. 构建 caller/callee 索引
        
        Returns:
            GitNexusEnrichment（.available=False 表示不可用）
        """
        enrichment = GitNexusEnrichment()
        
        try:
            # 1. 查找仓库
            if not repo_name:
                repo_name = self._match_repo(project_path)
            
            if not repo_name:
                # 尝试直接用 project_path 启动
                repos = self.list_repos()
                if isinstance(repos, list):
                    # 通过路径匹配
                    for r in repos:
                        r_path = ""
                        if isinstance(r, dict):
                            r_path = r.get("path", r.get("name", ""))
                        else:
                            r_path = str(r)
                        if r_path and (r_path in project_path or project_path in r_path):
                            repo_name = r["name"] if isinstance(r, dict) else r_path
                            break
            
            enrichment.repo_name = repo_name or os.path.basename(project_path)
            
            # 2. 获取全项目符号
            enrichment.all_symbols = self._fetch_all_symbols(repo_name)
            logger.info(f"[GitNexusEnrich] 获取到 {len(enrichment.all_symbols)} 个符号")
            
            # 3. 构建文件→符号索引
            enrichment.file_symbols = self._build_file_symbol_index(enrichment.all_symbols)
            
            # 4. 获取调用图
            enrichment.call_pairs = self._fetch_call_graph(repo_name)
            logger.info(f"[GitNexusEnrich] 获取到 {len(enrichment.call_pairs)} 条调用关系")
            
            # 5. 构建 caller/callee 索引
            enrichment.caller_index, enrichment.callee_index = \
                self._build_call_index(enrichment.call_pairs)
            
            # 6. 批量搜索业务关键词
            enrichment.search_results = self._batch_business_search(repo_name)
            
            # 7. 发现入口点（被最多调用的函数 = 核心入口）
            enrichment.entry_points = self._discover_entry_points(enrichment)
            
            enrichment.available = True
            logger.info(f"[GitNexusEnrich] 增强完成: {len(enrichment.file_symbols)} 个文件, "
                       f"{len(enrichment.call_pairs)} 条调用, "
                       f"{len(enrichment.entry_points)} 个入口点")
            
        except Exception as e:
            enrichment.error = str(e)
            logger.warning(f"[GitNexusEnrich] 增强失败: {e}")
            enrichment.available = False
        
        return enrichment
    
    def _match_repo(self, project_path: str) -> str:
        """通过项目路径匹配 GitNexus 仓库名"""
        try:
            repos = self.list_repos()
            if isinstance(repos, list):
                for r in repos:
                    if isinstance(r, dict):
                        r_path = r.get("path", r.get("dir", ""))
                        r_name = r.get("name", "")
                        if r_path:
                            if os.path.abspath(r_path) == os.path.abspath(project_path):
                                return r_name or os.path.basename(r_path)
                    elif isinstance(r, str):
                        if r.lower() in project_path.lower() or \
                           os.path.basename(project_path).lower() in r.lower():
                            return r
            return os.path.basename(project_path)
        except Exception:
            return os.path.basename(project_path)
    
    def _fetch_all_symbols(self, repo: str = "") -> List[Dict]:
        """通过 Cypher 获取全项目符号（GitNexus 返回 Markdown 表格格式）"""
        try:
            result = self.query_cypher(
                "MATCH (n) RETURN n.name, n.filePath LIMIT 3000",
                repo
            )
            symbols = self._parse_markdown_table(result, ['name', 'filePath'])
            if symbols:
                logger.info(f"[GitNexus] Cypher 获取到 {len(symbols)} 个符号")
                return symbols
        except Exception as e:
            logger.debug(f"[GitNexus] Cypher 全符号查询失败: {e}")
        
        # 降级方案：通过关键词搜索常用符号
        return self._fallback_symbol_discovery(repo)
    
    def _fallback_symbol_discovery(self, repo: str = "") -> List[Dict]:
        """降级方案：搜索常见模式来发现符号"""
        discovered = []
        # 搜索常见类名模式
        for kw in ["Service", "Handler", "Manager", "Controller", "Bot", "Agent",
                   "Tool", "Plugin", "Model", "View", "Window", "Dialog"]:
            try:
                results = self.search(kw, repo)
                items = self._normalize_search_results(results)
                for item in items:
                    name = item.get("name", item.get("symbol", ""))
                    if name and name not in [s.get("name") for s in discovered]:
                        discovered.append({
                            "name": name,
                            "filePath": item.get("filePath", item.get("file", "")),
                            "type": item.get("type", item.get("kind", "Unknown")),
                            "source": "search"
                        })
            except Exception:
                continue
        return discovered
    
    def _fetch_call_graph(self, repo: str = "") -> List[tuple]:
        """通过 Cypher 获取调用关系（GitNexus 返回 Markdown 表格格式）"""
        try:
            result = self.query_cypher(
                "MATCH (a)-[r]->(b) RETURN a.name, b.name LIMIT 3000",
                repo
            )
            pairs = self._parse_markdown_pairs(result, ['caller', 'callee'])
            if pairs:
                logger.info(f"[GitNexus] Cypher 获取到 {len(pairs)} 条调用关系")
                return pairs
        except Exception as e:
            logger.debug(f"[GitNexus] Cypher 调用图查询失败: {e}")
        
        return []
    
    def _parse_cypher_result(self, result: Any) -> List[Dict]:
        """解析 Cypher 查询结果"""
        symbols = []
        if isinstance(result, list):
            for item in result:
                if isinstance(item, dict):
                    s = {
                        "name": item.get("n.name", item.get("name", "")),
                        "filePath": item.get("n.filePath", item.get("filePath", "")),
                        "type": item.get("n.type", item.get("type", "")),
                        "startLine": item.get("n.startLine", item.get("startLine", 0)),
                        "language": item.get("n.language", ""),
                    }
                    if s["name"]:
                        symbols.append(s)
                elif isinstance(item, list) and len(item) >= 2:
                    symbols.append({
                        "name": str(item[0]),
                        "filePath": str(item[1]) if len(item) > 1 else "",
                    })
        elif isinstance(result, dict):
            # 尝试各种可能的键名
            for key in ["data", "rows", "records", "results", "nodes"]:
                data = result.get(key, [])
                if isinstance(data, list):
                    return self._parse_cypher_result(data)
        return symbols
    
    def _parse_cypher_pairs(self, result: Any) -> List[tuple]:
        """解析 Cypher 返回的调用关系对"""
        pairs = []
        if isinstance(result, list):
            for item in result:
                if isinstance(item, dict):
                    caller = item.get("a.name", item.get("caller", item.get("source", "")))
                    callee = item.get("b.name", item.get("callee", item.get("target", "")))
                    rel_type = item.get("type(r)", item.get("relation", ""))
                    if caller and callee:
                        pairs.append((caller, callee, rel_type))
                elif isinstance(item, list) and len(item) >= 2:
                    pairs.append((str(item[0]), str(item[1]), str(item[2]) if len(item) > 2 else "CALLS"))
        elif isinstance(result, dict):
            for key in ["data", "rows", "records", "edges", "relationships"]:
                data = result.get(key, [])
                if isinstance(data, list):
                    return self._parse_cypher_pairs(data)
        return pairs
    
    def _parse_markdown_table(self, result: Any, columns: List[str]) -> List[Dict]:
        """
        解析 GitNexus Cypher 查询返回的 Markdown 表格格式
        
        GitNexus 的 Cypher 返回格式:
        {'markdown': '| col1 | col2 |\\n| --- | --- |\\n| val1 | val2 |\\n...', 'row_count': N}
        """
        if not isinstance(result, dict):
            # 如果不是 dict，回退到旧解析器
            return self._parse_cypher_result(result)
        
        md = result.get('markdown', '')
        if not md:
            # 如果没有 markdown 字段，也回退
            return self._parse_cypher_result(result)
        
        lines = md.strip().split('\n')
        if len(lines) < 3:
            return []
        
        # 跳过表头和分隔行
        data_lines = [l for l in lines if l.strip() and '| ---' not in l]
        if not data_lines:
            return []
        data_lines = data_lines[1:]  # 去掉表头行
        
        parsed = []
        for line in data_lines:
            cells = [c.strip() for c in line.split('|') if c.strip()]
            if len(cells) < len(columns):
                continue
            row = {}
            for i, col in enumerate(columns):
                if i < len(cells):
                    val = cells[i]
                    row[col] = val if val and val != 'null' and val != 'undefined' else ''
            if row.get(columns[0]):  # 至少第一个字段非空
                parsed.append(row)
        
        return parsed

    def _parse_markdown_pairs(self, result: Any, columns: List[str]) -> List[tuple]:
        """
        解析 Markdown 表格为二元组列表（调用关系对）
        
        Returns:
            [(caller, callee, relation_type), ...]
        """
        rows = self._parse_markdown_table(result, columns)
        pairs = []
        for row in rows:
            caller = row.get(columns[0], '').strip()
            callee = row.get(columns[1], '').strip()
            if caller and callee and caller != callee:
                pairs.append((caller, callee, 'CALLS'))
        return pairs

    def _build_file_symbol_index(self, symbols: List[Dict]) -> Dict[str, List[Dict]]:
        """构建 文件路径 → [符号列表] 索引"""
        index = {}
        for s in symbols:
            fp = s.get("filePath", s.get("file_path", ""))
            if not fp:
                continue
            index.setdefault(fp.replace('\\', '/'), []).append(s)
        return index
    
    def _build_call_index(self, pairs: List[tuple]) -> tuple:
        """构建 caller/callee 双向索引"""
        caller_idx = {}  # callee → [callers...]
        callee_idx = {}  # caller → [callees...]
        for caller, callee, rel in pairs:
            callee_idx.setdefault(caller, []).append(callee)
            caller_idx.setdefault(callee, []).append(caller)
        return caller_idx, callee_idx
    
    def _batch_business_search(self, repo: str = "") -> Dict[str, List[Dict]]:
        """批量搜索业务关键词"""
        keywords = ["api", "route", "service", "handler", "process", "flow",
                    "run", "execute", "start", "main", "entry", "index",
                    "login", "auth", "config", "setting"]
        results = {}
        for kw in keywords:
            try:
                r = self.search(kw, repo)
                items = self._normalize_search_results(r)
                if items:
                    results[kw] = items[:10]
            except Exception:
                continue
        return results
    
    def _normalize_search_results(self, result: Any) -> List[Dict]:
        """归一化搜索结果到统一格式"""
        items = []
        if isinstance(result, list):
            for item in result:
                if isinstance(item, dict):
                    items.append(item)
                elif isinstance(item, str):
                    items.append({"name": item})
        elif isinstance(result, dict):
            for key in ["results", "data", "matches", "items", "symbols"]:
                data = result.get(key, [])
                if isinstance(data, list):
                    return self._normalize_search_results(data)
                    break
        return items
    
    def _discover_entry_points(self, enrichment: 'GitNexusEnrichment') -> List[str]:
        """
        发现核心入口点：
        - 被最多其他符号调用的函数 = 核心入口
        - 名为 main/run/start/entry 的函数
        """
        # 按被调用次数排序
        call_count = {}
        for caller, callees in enrichment.callee_index.items():
            for callee in callees:
                call_count[callee] = call_count.get(callee, 0) + 1
        
        # 找出调用次数最多的符号
        sorted_by_refs = sorted(call_count.items(), key=lambda x: -x[1])
        
        entry_points = []
        # 高引用符号作为入口
        for name, count in sorted_by_refs:
            if count >= 2:
                entry_points.append(name)
            if len(entry_points) >= 10:
                break
        
        # 补充常见入口名
        common_entry_keywords = ["main", "run", "start", "entry", "index", "setup", "init"]
        for s in enrichment.all_symbols:
            if any(kw in s.get("name", "").lower() for kw in common_entry_keywords):
                name = s.get("name", "")
                if name and name not in entry_points:
                    entry_points.append(name)
        
        return entry_points[:15]

    @staticmethod
    def is_cli_available() -> bool:
        """检查GitNexus CLI是否可用（通过npx）"""
        try:
            result = subprocess.run(
                "npx -y gitnexus --version",
                capture_output=True,
                text=True,
                timeout=30,
                shell=True
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def get_version() -> str:
        """获取GitNexus版本号"""
        try:
            result = subprocess.run(
                "npx -y gitnexus --version",
                capture_output=True,
                text=True,
                timeout=30,
                shell=True
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return "unknown"
