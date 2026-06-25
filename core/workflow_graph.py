# -*- coding: utf-8 -*-
"""
交互式流程画布 — 基于 GitNexus 索引数据渲染节点式架构图

借鉴 Dify/toolGraph 的交互理念，但面向"已有代码的逆向可视化"：
- 不是设计时拖拽编排，而是从代码中自动提取节点和连线
- 支持点击节点展开上下游、拖拽平移、滚轮缩放
- 按 GitNexus cluster 自动分层着色
- 叠加精简审计结果的问题高亮

输出：纯静态 HTML 文件，浏览器直接打开，无需后端服务。

用法：
    from core.workflow_graph import WorkflowGraph

    graph = WorkflowGraph()
    html_path = graph.generate(project_path="d:/c/coding/marketing/working")
    # 返回 HTML 文件路径，浏览器打开即可

作者: PersuadeAI Team
版本: v1.0
"""

import os
import json
import re
import html
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict

from loguru import logger


# ═══════════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════════

class WorkflowGraph:
    """
    交互式流程画布生成器

    从 GitNexus 索引中提取全部节点和边，渲染为可交互的 HTML 节点画布。
    叠加 CodeSimplifier 的精简审计结果，高亮问题节点。

    交互特性：
    - 点击节点：展开/收起上下游连接
    - 拖拽：平移画布
    - 滚轮：缩放
    - 悬浮：显示节点详情（文件路径、行数、类型）
    - 问题高亮：红色（critical）、橙色（high）、黄色（medium）
    - 图例：按 cluster 分层着色
    """

    # 分层配色（8 层，对应 auto_classifier 的 5 层 + 3 个扩展）
    LAYER_COLORS = [
        "#3B82F6",  # 入口层 - 蓝
        "#10B981",  # 核心层 - 绿
        "#F59E0B",  # 数据层 - 橙
        "#8B5CF6",  # 共享层 - 紫
        "#6B7280",  # 其他 - 灰
        "#EF4444",  # 扩展1 - 红
        "#06B6D4",  # 扩展2 - 青
        "#EC4899",  # 扩展3 - 粉
    ]

    SEVERITY_COLORS = {
        "critical": "#EF4444",
        "high": "#F97316",
        "medium": "#EAB308",
        "low": "#6B7280",
    }

    def __init__(self):
        pass

    def generate(
        self,
        project_path: str,
        output_dir: Optional[str] = None,
        title: str = "项目架构流程画布",
        simplification_items: Optional[List[Dict]] = None,
    ) -> str:
        """
        生成交互式流程画布 HTML

        Args:
            project_path: 项目路径
            output_dir: 输出目录（默认 project_path 下的 .gitnexus/）
            title: 画布标题
            simplification_items: 精简审计结果（来自 CodeSimplifier），用于高亮问题节点

        Returns:
            HTML 文件路径
        """
        import subprocess

        # 1. 确定输出目录
        if not output_dir:
            output_dir = os.path.join(project_path, ".gitnexus")
        os.makedirs(output_dir, exist_ok=True)

        # 2. 从 GitNexus 获取数据
        logger.info(f"[WorkflowGraph] 查询 GitNexus 索引: {project_path}")
        nodes, edges = self._fetch_graph_data(project_path)

        if not nodes:
            logger.warning("[WorkflowGraph] GitNexus 无数据，尝试降级为 CodeAnalyzer 模式")
            nodes, edges = self._fallback_code_analyzer(project_path)

        logger.info(f"[WorkflowGraph] 节点: {len(nodes)}, 边: {len(edges)}")

        # 3. 叠加精简审计结果
        issue_map = self._build_issue_map(simplification_items)

        # 4. 生成 HTML
        html_content = self._render_html(
            nodes=nodes,
            edges=edges,
            title=title,
            project_path=project_path,
            issue_map=issue_map,
        )

        # 5. 写入文件
        filename = f"workflow_graph_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join(output_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        logger.info(f"[WorkflowGraph] 画布已生成: {filepath} ({len(html_content):,} bytes)")
        return filepath

    def _fetch_graph_data(self, project_path: str) -> Tuple[List[Dict], List[Dict]]:
        """通过 GitNexus MCP 获取全量节点和边"""
        from core.gitnexus_client import GitNexusMCPClient

        nodes = []
        edges = []

        try:
            with GitNexusMCPClient(project_path) as client:
                # 1. 获取全量符号（节点）
                symbols = self._fetch_all_symbols(client)
                nodes = self._build_nodes(symbols)

                # 2. 获取调用关系（边）
                call_pairs = self._fetch_call_pairs(client)
                edges = self._build_edges(call_pairs, {n["id"] for n in nodes})

                # 3. 获取 cluster 信息
                clusters = self._fetch_clusters(client)
                if clusters:
                    nodes = self._apply_clusters(nodes, clusters)

        except Exception as e:
            logger.warning(f"[WorkflowGraph] GitNexus 查询失败: {e}")

        return nodes, edges

    def _fetch_all_symbols(self, client) -> List[Dict]:
        """获取全量符号"""
        result = client.query_cypher(
            "MATCH (n) RETURN n.name, n.filePath, n.startLine, n.endLine, n.language LIMIT 5000"
        )
        parsed = client._parse_markdown_table(result, ["name", "filePath", "startLine", "endLine", "language"])
        return parsed

    def _fetch_call_pairs(self, client) -> List[Tuple]:
        """获取调用关系（指定关系类型 + 多格式兼容）"""
        # 尝试指定关系类型，如果不支持则回退到通用查询
        result = None
        for query in [
            "MATCH (a)-[r:CALLS|IMPORTS|EXTENDS|INVOKES|DEPENDS_ON]->(b) RETURN a.name, b.name, type(r) LIMIT 5000",
            "MATCH (a)-[r]->(b) RETURN a.name, b.name, type(r) LIMIT 5000",
        ]:
            try:
                result = client.query_cypher(query)
                parsed = client._parse_markdown_pairs(result, ["caller", "callee", "rel_type"])
                if parsed:
                    logger.info(f"[WorkflowGraph] 获取到 {len(parsed)} 条调用关系")
                    return parsed
            except Exception as e:
                logger.warning(f"[WorkflowGraph] Cypher 查询失败，尝试下一个: {e}")
                continue

        # 降级：尝试从 context 工具获取
        try:
            logger.info("[WorkflowGraph] 降级：使用 context 工具获取调用关系")
            context_result = client._call_tool("context", {"entry": "", "depth": 3})
            # 尝试从 context 返回中提取调用关系
            if isinstance(context_result, dict):
                incoming = context_result.get("incoming", {})
                outgoing = context_result.get("outgoing", {})
                pairs = []
                for cat in ["calls", "callers", "imports", "references"]:
                    for item in outgoing.get(cat, []) + incoming.get(cat, []):
                        if isinstance(item, dict):
                            pairs.append((item.get("name", ""), item.get("caller", ""), item.get("type", "")))
                if pairs:
                    return pairs
        except Exception as e:
            logger.warning(f"[WorkflowGraph] context 降级也失败: {e}")

        logger.warning("[WorkflowGraph] 未能获取调用关系数据，边将为空")
        return []

    def _fetch_clusters(self, client) -> Dict[str, str]:
        """获取 cluster 信息"""
        clusters = {}
        try:
            # 尝试查询 community/cluster 属性
            result = client.query_cypher(
                "MATCH (n) WHERE n.community IS NOT NULL RETURN n.name, n.community LIMIT 5000"
            )
            parsed = client._parse_markdown_table(result, ["name", "community"])
            for row in parsed:
                name = row.get("name", "")
                community = row.get("community", "")
                if name and community:
                    clusters[name] = community
        except Exception:
            pass
        return clusters

    def _build_nodes(self, symbols: List[Dict]) -> List[Dict]:
        """构建节点列表"""
        nodes = []
        seen = set()
        for s in symbols:
            name = s.get("name", "").strip()
            if not name or name in seen:
                continue
            seen.add(name)
            fp = s.get("filePath", "")
            start_line = int(s.get("startLine", 0) or 0)
            end_line = int(s.get("endLine", 0) or 0)
            line_count = max(1, end_line - start_line + 1) if end_line > start_line else 1

            node = {
                "id": name,
                "label": self._shorten_label(name),
                "fullName": name,
                "filePath": fp,
                "lineCount": line_count,
                "language": s.get("language", ""),
                "layer": self._classify_layer(fp, name),
                "cluster": "",
            }
            nodes.append(node)
        return nodes

    def _build_edges(self, call_pairs: List[Tuple], node_ids: set) -> List[Dict]:
        """构建边列表"""
        edges = []
        seen = set()
        for row in call_pairs:
            if len(row) >= 2:
                caller, callee = str(row[0]).strip(), str(row[1]).strip()
            else:
                continue
            if not caller or not callee or caller == callee:
                continue
            if caller not in node_ids or callee not in node_ids:
                continue
            key = (caller, callee)
            if key in seen:
                continue
            seen.add(key)
            edges.append({
                "from": caller,
                "to": callee,
                "arrows": "to",
                "color": {"color": "#94A3B8", "opacity": 0.4},
            })
        return edges

    def _apply_clusters(self, nodes: List[Dict], clusters: Dict[str, str]) -> List[Dict]:
        """应用 cluster 信息到节点"""
        for node in nodes:
            name = node["id"]
            if name in clusters:
                node["cluster"] = clusters[name]
        return nodes

    def _classify_layer(self, file_path: str, name: str) -> int:
        """自动分层：根据文件路径和名称推断节点所属层级"""
        fp_lower = file_path.lower()
        name_lower = name.lower()

        # 入口层：路由、控制器、入口点
        if any(kw in fp_lower for kw in ["route", "controller", "handler", "api", "view", "gui", "window"]):
            return 0
        if any(kw in name_lower for kw in ["main", "run", "start", "entry", "index", "app"]):
            return 0

        # 核心层：服务、业务逻辑
        if any(kw in fp_lower for kw in ["service", "core", "engine", "business", "logic", "domain", "agent"]):
            return 1
        if any(kw in name_lower for kw in ["service", "engine", "manager", "processor", "handler", "analyzer"]):
            return 1

        # 数据层：数据库、存储、模型
        if any(kw in fp_lower for kw in ["model", "data", "db", "database", "store", "repo", "entity", "schema"]):
            return 2
        if any(kw in name_lower for kw in ["model", "store", "repo", "db", "entity", "schema"]):
            return 2

        # 共享层：工具、配置
        if any(kw in fp_lower for kw in ["util", "shared", "common", "config", "helper", "lib"]):
            return 3

        # 其他
        return 4

    def _shorten_label(self, name: str) -> str:
        """缩短节点标签（截断到 20 字符）"""
        if len(name) <= 20:
            return name
        return name[:18] + "…"

    def _fallback_code_analyzer(self, project_path: str) -> Tuple[List[Dict], List[Dict]]:
        """降级方案：使用 CodeAnalyzer 获取基础数据"""
        from core.code_analyzer import CodeAnalyzer

        nodes = []
        edges = []

        try:
            analyzer = CodeAnalyzer()
            analysis = analyzer.analyze_project(project_path)

            for cf in analysis.files:
                for func in cf.functions:
                    node_id = f"{cf.file_path}:{func.name}"
                    nodes.append({
                        "id": node_id,
                        "label": self._shorten_label(func.name),
                        "fullName": func.name,
                        "filePath": cf.file_path,
                        "lineCount": func.end_line - func.start_line + 1,
                        "language": cf.language,
                        "layer": self._classify_layer(cf.file_path, func.name),
                        "cluster": "",
                    })

                for cls in cf.classes:
                    node_id = f"{cf.file_path}:{cls.name}"
                    nodes.append({
                        "id": node_id,
                        "label": self._shorten_label(cls.name),
                        "fullName": cls.name,
                        "filePath": cf.file_path,
                        "lineCount": cls.end_line - cls.start_line + 1,
                        "language": cf.language,
                        "layer": self._classify_layer(cf.file_path, cls.name),
                        "cluster": "",
                    })

        except Exception as e:
            logger.warning(f"[WorkflowGraph] CodeAnalyzer 降级失败: {e}")

        return nodes, edges

    def _build_issue_map(self, items: Optional[List[Dict]]) -> Dict[str, Dict]:
        """构建问题映射：文件路径 → 问题列表"""
        issue_map = defaultdict(list)
        if not items:
            return issue_map

        for item in items:
            fp = item.get("file_path", "")
            if fp:
                issue_map[fp].append({
                    "severity": item.get("severity", "low"),
                    "title": item.get("title", ""),
                    "category": item.get("category", ""),
                    "line_range": item.get("line_range", [0, 0]),
                })
        return issue_map

    def _render_html(
        self,
        nodes: List[Dict],
        edges: List[Dict],
        title: str,
        project_path: str,
        issue_map: Dict[str, List[Dict]],
    ) -> str:
        """生成 HTML 画布"""
        # 序列化数据
        nodes_json = json.dumps(nodes, ensure_ascii=False)
        edges_json = json.dumps(edges, ensure_ascii=False)
        issue_map_json = json.dumps(issue_map, ensure_ascii=False)
        layer_colors_json = json.dumps(self.LAYER_COLORS)
        severity_colors_json = json.dumps(self.SEVERITY_COLORS)

        return f'''<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(title)}</title>
<script src="https://unpkg.com/vis-network@9.1.9/dist/vis-network.min.js"></script>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: "Segoe UI", "Noto Sans CJK SC", sans-serif; overflow: hidden; background: #0F172A; }}
#toolbar {{ position: absolute; top: 0; left: 0; right: 0; z-index: 100; background: rgba(15,23,42,0.95); backdrop-filter: blur(10px); padding: 10px 16px; display: flex; align-items: center; gap: 12px; border-bottom: 1px solid #1E293B; }}
#toolbar h1 {{ font-size: 16px; color: #E2E8F0; font-weight: 600; white-space: nowrap; }}
#toolbar .stats {{ font-size: 12px; color: #64748B; }}
#toolbar .spacer {{ flex: 1; }}
#toolbar button {{ background: #1E293B; color: #E2E8F0; border: 1px solid #334155; padding: 6px 12px; border-radius: 6px; cursor: pointer; font-size: 12px; transition: all .15s; }}
#toolbar button:hover {{ background: #334155; border-color: #475569; }}
#toolbar button.active {{ background: #3B82F6; border-color: #3B82F6; }}
#legend {{ position: absolute; bottom: 16px; left: 16px; z-index: 100; background: rgba(15,23,42,0.95); padding: 10px 14px; border-radius: 8px; border: 1px solid #1E293B; font-size: 11px; color: #94A3B8; }}
#legend .item {{ display: flex; align-items: center; gap: 6px; margin: 3px 0; }}
#legend .dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
#detail {{ position: absolute; top: 60px; right: 16px; z-index: 100; background: rgba(15,23,42,0.95); padding: 14px; border-radius: 8px; border: 1px solid #1E293B; max-width: 300px; display: none; font-size: 12px; color: #E2E8F0; }}
#detail h3 {{ font-size: 14px; margin-bottom: 6px; color: #60A5FA; word-break: break-all; }}
#detail .field {{ margin: 4px 0; color: #94A3B8; }}
#detail .field span {{ color: #E2E8F0; }}
#detail .issues {{ margin-top: 8px; padding-top: 8px; border-top: 1px solid #1E293B; }}
#detail .issue {{ padding: 3px 6px; margin: 2px 0; border-radius: 4px; font-size: 11px; }}
#network {{ width: 100vw; height: 100vh; }}
#loading {{ position: absolute; top: 50%; left: 50%; transform: translate(-50%,-50%); color: #64748B; font-size: 14px; }}
</style>
</head>
<body>
<div id="toolbar">
  <h1>🔍 {html.escape(title)}</h1>
  <span class="stats">节点: {len(nodes)} | 边: {len(edges)}</span>
  <span class="spacer"></span>
  <button onclick="fitAll()" title="适应画布">📐 适应</button>
  <button id="btnIssues" onclick="toggleIssues()" title="高亮问题节点">⚠️ 问题</button>
  <button onclick="resetView()" title="重置视图">🔄 重置</button>
</div>
<div id="detail"></div>
<div id="legend">
  <div style="font-weight:600;margin-bottom:4px;color:#E2E8F0;">分层图例</div>
  <div class="item"><div class="dot" style="background:#3B82F6"></div>入口层</div>
  <div class="item"><div class="dot" style="background:#10B981"></div>核心层</div>
  <div class="item"><div class="dot" style="background:#F59E0B"></div>数据层</div>
  <div class="item"><div class="dot" style="background:#8B5CF6"></div>共享层</div>
  <div class="item"><div class="dot" style="background:#6B7280"></div>其他</div>
  <div style="margin-top:6px;font-weight:600;color:#E2E8F0;">交互</div>
  <div style="color:#64748B;">点击节点展开 | 滚轮缩放 | 拖拽平移</div>
</div>
<div id="loading">⏳ 加载中...</div>
<div id="network"></div>
<script>
const NODES = {nodes_json};
const EDGES = {edges_json};
const ISSUES = {issue_map_json};
const LAYER_COLORS = {layer_colors_json};
const SEVERITY_COLORS = {severity_colors_json};
const PROJECT_PATH = {json.dumps(project_path)};

let showIssues = false;
let network = null;
let allNodesData = [];
let allEdgesData = [];

function buildNodeData(n) {{
    const layer = n.layer || 0;
    const color = LAYER_COLORS[layer % LAYER_COLORS.length];
    const size = Math.max(8, Math.min(30, 6 + Math.log2(n.lineCount || 1) * 5));
    const fileIssues = ISSUES[n.filePath] || [];
    const hasIssues = fileIssues.length > 0;
    const maxSev = fileIssues.reduce((m, i) => {{
        const order = {{critical:3,high:2,medium:1,low:0}};
        return order[i.severity] > order[m] ? i.severity : m;
    }}, "low");

    return {{
        id: n.id,
        label: n.label,
        title: _buildTooltip(n),
        color: hasIssues ? SEVERITY_COLORS[maxSev] || color : color,
        borderWidth: hasIssues ? 2 : 1,
        borderWidthSelected: 3,
        size: size,
        font: {{ color: "#E2E8F0", size: 11, face: "monospace" }},
        shape: "dot",
        _fullName: n.fullName,
        _filePath: n.filePath,
        _lineCount: n.lineCount,
        _language: n.language,
        _layer: layer,
        _cluster: n.cluster,
        _issues: fileIssues,
    }};
}}

function buildEdgeData(e) {{
    return {{
        from: e.from,
        to: e.to,
        arrows: e.arrows || "to",
        color: e.color || {{ color: "#94A3B8", opacity: 0.4 }},
        smooth: {{ type: "continuous", roundness: 0.3 }},
    }};
}}

function _buildTooltip(n) {{
    let tip = `<b>${{n.label}}</b><br>`;
    if (n.filePath) tip += `📁 ${{n.filePath}}<br>`;
    if (n.lineCount) tip += `📏 ${{n.lineCount}} 行<br>`;
    if (n.language) tip += `🔤 ${{n.language}}<br>`;
    const issues = ISSUES[n.filePath] || [];
    if (issues.length) tip += `⚠️ ${{issues.length}} 个问题<br>`;
    tip += "<i>点击展开上下游</i>";
    return tip;
}}

// 初始化
function init() {{
    // 构建节点
    const nodeSet = new Set(NODES.map(n => n.id));
    allNodesData = NODES.map(n => buildNodeData(n));
    allEdgesData = EDGES.filter(e => nodeSet.has(e.from) && nodeSet.has(e.to)).map(e => buildEdgeData(e));

    // 只显示核心节点（被调用次数多的）和入口节点
    const edgeCount = {{}};
    allEdgesData.forEach(e => {{
        edgeCount[e.to] = (edgeCount[e.to] || 0) + 1;
        edgeCount[e.from] = (edgeCount[e.from] || 0) + 1;
    }});

    // 取被引用最多的前 200 个节点 + 入口节点
    const topNodes = Object.entries(edgeCount)
        .sort((a,b) => b[1] - a[1])
        .slice(0, 200)
        .map(e => e[0]);

    const entryNodes = allNodesData.filter(n => n._layer === 0).map(n => n.id);
    const initialIds = new Set([...topNodes, ...entryNodes].slice(0, 250));

    const initialNodes = allNodesData.filter(n => initialIds.has(n.id));
    const initialEdges = allEdgesData.filter(e => initialIds.has(e.from) && initialIds.has(e.to));

    const container = document.getElementById("network");
    document.getElementById("loading").style.display = "none";

    const options = {{
        physics: {{
            solver: "forceAtlas2Based",
            forceAtlas2Based: {{
                gravitationalConstant: -50,
                centralGravity: 0.01,
                springLength: 120,
                springConstant: 0.08,
                damping: 0.4,
            }},
            stabilization: {{ iterations: 100 }},
        }},
        interaction: {{
            hover: true,
            tooltipDelay: 200,
            zoomView: true,
            dragView: true,
            navigationButtons: false,
        }},
        nodes: {{
            borderWidth: 1,
            borderWidthSelected: 3,
            color: {{ border: "#1E293B", background: "#3B82F6", highlight: {{ border: "#60A5FA", background: "#60A5FA" }} }},
        }},
        edges: {{
            width: 1,
            selectionWidth: 2,
            smooth: {{ type: "continuous", roundness: 0.3 }},
        }},
    }};

    network = new vis.Network(container, {{ nodes: new vis.DataSet(initialNodes), edges: new vis.DataSet(initialEdges) }}, options);

    // 点击事件：展开节点
    network.on("click", function(params) {{
        if (params.nodes.length > 0) {{
            const nodeId = params.nodes[0];
            expandNode(nodeId);
            showDetail(nodeId);
        }} else {{
            document.getElementById("detail").style.display = "none";
        }}
    }});

    // 双击：聚焦该节点
    network.on("doubleClick", function(params) {{
        if (params.nodes.length > 0) {{
            network.focus(params.nodes[0], {{ scale: 1.5, animation: true }});
        }}
    }});

    // 稳定后自适应
    network.once("stabilizationIterationsDone", function() {{
        network.fit({{ animation: true }});
    }});
}}

function expandNode(nodeId) {{
    // 获取该节点的上下游
    const upstream = allEdgesData.filter(e => e.to === nodeId).map(e => e.from);
    const downstream = allEdgesData.filter(e => e.from === nodeId).map(e => e.to);
    const related = [...new Set([nodeId, ...upstream, ...downstream])];

    // 添加相关节点
    const existingIds = new Set(network.body.data.nodes.getIds());
    const toAdd = related.filter(id => !existingIds.has(id));
    if (toAdd.length > 0) {{
        const newNodes = allNodesData.filter(n => toAdd.includes(n.id));
        const newEdges = allEdgesData.filter(e => toAdd.includes(e.from) || toAdd.includes(e.to));
        network.body.data.nodes.add(newNodes);
        network.body.data.edges.add(newEdges);
        network.fit({{ animation: {{ duration: 500, easingFunction: "easeInOutQuad" }} }});
    }}
}}

function showDetail(nodeId) {{
    const node = allNodesData.find(n => n.id === nodeId);
    if (!node) return;

    const detail = document.getElementById("detail");
    const issues = node._issues || [];
    let html = `<h3>${{node._fullName || nodeId}}</h3>`;
    if (node._filePath) html += `<div class="field">📁 <span>${{node._filePath}}</span></div>`;
    if (node._lineCount) html += `<div class="field">📏 <span>${{node._lineCount}} 行</span></div>`;
    if (node._language) html += `<div class="field">🔤 <span>${{node._language}}</span></div>`;
    html += `<div class="field">📊 <span>第 ${{node._layer + 1}} 层</span></div>`;
    if (node._cluster) html += `<div class="field">📦 <span>${{node._cluster}}</span></div>`;

    if (issues.length > 0) {{
        html += `<div class="issues"><b>⚠️ 精简建议 (${{issues.length}})</b></div>`;
        issues.forEach(iss => {{
            const bg = SEVERITY_COLORS[iss.severity] || "#6B7280";
            html += `<div class="issue" style="background:${{bg}}22;border-left:3px solid ${{bg}}">${{iss.title}}</div>`;
        }});
    }}

    detail.innerHTML = html;
    detail.style.display = "block";
}}

function toggleIssues() {{
    showIssues = !showIssues;
    const btn = document.getElementById("btnIssues");
    btn.classList.toggle("active", showIssues);

    if (showIssues) {{
        // 高亮所有有问题的节点，添加边框脉冲
        allNodesData.forEach(n => {{
            const issues = n._issues || [];
            if (issues.length > 0) {{
                const maxSev = issues.reduce((m, i) => {{
                    const order = {{critical:3,high:2,medium:1,low:0}};
                    return order[i.severity] > order[m] ? i.severity : m;
                }}, "low");
                const sevColor = SEVERITY_COLORS[maxSev] || "#6B7280";
                try {{
                    network.body.data.nodes.update({{ id: n.id, borderWidth: 3, color: {{ background: sevColor, border: "#FFF", highlight: {{ border: "#FFF" }} }} }});
                }} catch(e) {{}}
            }}
        }});
    }} else {{
        // 恢复原始颜色
        allNodesData.forEach(n => {{
            const layer = n._layer || 0;
            const color = LAYER_COLORS[layer % LAYER_COLORS.length];
            try {{
                network.body.data.nodes.update({{ id: n.id, borderWidth: (n._issues || []).length > 0 ? 2 : 1, color: {{ background: color, border: "#1E293B", highlight: {{ border: "#60A5FA" }} }} }});
            }} catch(e) {{}}
        }});
    }}
}}

function fitAll() {{ network.fit({{ animation: true }}); }}
function resetView() {{ network.fit({{ animation: true }}); showIssues = false; document.getElementById("btnIssues").classList.remove("active"); init(); }}

window.addEventListener("DOMContentLoaded", init);
</script>
</body>
</html>'''
