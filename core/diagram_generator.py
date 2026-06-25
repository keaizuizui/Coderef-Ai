"""
V1: 动态架构图生成器 —— 从子图数据生成Mermaid/Structurizr图表

支持：
- Mermaid flowchart（默认，轻量级）
- Structurizr DSL（正式C4模型）
- 自动按层级分组、高亮入口点
"""

from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field

# 启发式分层顺序（按路径名称关键词匹配）
LAYER_ORDER = [
    "entry", "controller", "gateway", "api", "presentation",
    "service", "core", "business", "domain", "logic",
    "data", "model", "repository", "dao",
    "infrastructure", "shared", "utils", "common", "util",
]

LAYER_LABELS = {
    "entry": "Entry Layer",
    "controller": "Controller Layer",
    "api": "API Layer",
    "service": "Service Layer",
    "core": "Core Layer",
    "business": "Business Layer",
    "domain": "Domain Layer",
    "data": "Data Layer",
    "repository": "Repository Layer",
    "infrastructure": "Infrastructure Layer",
    "shared": "Shared Utilities",
    "utils": "Shared Utilities",
}

def classify_nodes(nodes):
    """基于路径关键词对节点进行简单分层（启发式）
    
    每个节点根据路径中包含的关键词分配到对应层级，
    不匹配则归为 'other'
    """
    groups = {}
    for layer in list(LAYER_ORDER) + ["other"]:
        groups[layer] = []
    
    for node in nodes:
        name = node.get("name", "").lower()
        assigned = False
        for layer in LAYER_ORDER:
            if layer in name:
                groups[layer].append(node)
                assigned = True
                break
        if not assigned:
            groups["other"].append(node)
    
    return groups


def sanitize_id(name: str) -> str:
    """将名称转换为合法的Mermaid节点ID"""
    import re
    # 移除特殊字符，保留字母数字下划线
    clean = re.sub(r'[^a-zA-Z0-9_\u4e00-\u9fff]', '_', name)
    # 确保不以数字开头
    if clean and clean[0].isdigit():
        clean = 'n' + clean
    return clean[:60]  # 截断过长ID


def generate_mermaid(
    nodes: List[Dict],
    edges: List[Dict],
    entry_point: str = "",
    title: str = "Architecture Overview",
    direction: str = "TD",
) -> str:
    """从子图数据生成Mermaid图
    
    Args:
        nodes: 节点列表 [{filePath, name, ...}]
        edges: 边列表 [{source, target, relation_type, ...}]
        entry_point: 入口点名称（高亮显示）
        title: 图标题
        direction: 方向 (TD=上到下, LR=左到右)
    
    Returns:
        Mermaid代码字符串
    """
    # 分类节点
    groups = classify_nodes(nodes)
    
    # 构建节点ID映射
    node_ids = {}
    for node in nodes:
        name = node.get("name", node.get("qualified_name", ""))
        node_id = sanitize_id(name)
        node_ids[name] = node_id
    
    # 入口点ID
    entry_id = sanitize_id(entry_point) if entry_point else ""
    
    lines = [f"graph {direction}"]
    lines.append(f'    title["{title}"]')
    
    # 按层级生成子图
    for layer_name in LAYER_ORDER:
        layer_nodes = groups.get(layer_name, [])
        if not layer_nodes:
            continue
        
        label = LAYER_LABELS.get(layer_name, layer_name)
        lines.append(f'    subgraph {layer_name} ["{label}"]')
        
        for node in layer_nodes:
            name = node.get("name", "")
            node_id = node_ids.get(name, sanitize_id(name))
            # 截断显示名称
            display_name = name if len(name) <= 30 else name[:27] + "..."
            lines.append(f'        {node_id}["{display_name}"]')
        
        lines.append(f'    end')
    
    # 生成边
    for edge in edges:
        source_name = edge.get("source", "")
        target_name = edge.get("target", "")
        source_id = node_ids.get(source_name, sanitize_id(source_name))
        target_id = node_ids.get(target_name, sanitize_id(target_name))
        relation = edge.get("relation_type", "")
        
        if relation:
            lines.append(f'    {source_id} -->|{relation}| {target_id}')
        else:
            lines.append(f'    {source_id} --> {target_id}')
    
    # 高亮入口点
    if entry_id and entry_id in [nid for nid in node_ids.values()]:
        lines.append(f'    style {entry_id} fill:#f96,stroke:#333,stroke-width:4px')
    
    return "\n".join(lines)


def generate_structurizr(
    project_name: str,
    nodes: List[Dict],
    edges: List[Dict],
    entry_point: str = "",
) -> str:
    """从子图数据生成Structurizr DSL
    
    Args:
        project_name: 项目名称
        nodes: 节点列表
        edges: 边列表
        entry_point: 入口点名称
    
    Returns:
        Structurizr DSL字符串
    """
    groups = classify_nodes(nodes)
    
    entry_id = sanitize_id(entry_point) if entry_point else ""
    
    # 生成容器定义
    containers = []
    for layer_name in LAYER_ORDER:
        layer_nodes = groups.get(layer_name, [])
        for node in layer_nodes:
            name = node.get("name", "")
            node_id = sanitize_id(name)
            c4_type = node.get("_c4_type", "Component")
            tag = node.get("_layer", "Other")
            containers.append(f'        {node_id} = {c4_type.lower()} "{name}" {{ tags "{tag}" }}')
    
    # 生成关系
    relationships = []
    for edge in edges:
        source_name = edge.get("source", "")
        target_name = edge.get("target", "")
        source_id = sanitize_id(source_name)
        target_id = sanitize_id(target_name)
        relation = edge.get("relation_type", "Calls")
        relationships.append(f'        {source_id} --> {target_id} "{relation}"')
    
    # 入口点关系
    entry_relations = []
    if entry_id:
        entry_relations.append(f'        user -> {entry_id} "Triggers"')
    
    dsl = f"""workspace {{
    model {{
        user = person "User"
        system = softwareSystem "{project_name}" {{
{chr(10).join(containers)}
        }}
{chr(10).join(entry_relations)}
{chr(10).join(relationships)}
    }}
    views {{
        container system {{
            include *
            autolayout
        }}
    }}
}}"""
    
    return dsl


def generate_report_markdown(
    project_name: str,
    nodes: List[Dict],
    edges: List[Dict],
    entry_point: str = "",
    mermaid_code: str = "",
    risk_summary: str = "",
    upstream: List[str] = None,
    downstream: List[str] = None,
) -> str:
    """生成完整的Markdown报告
    
    Args:
        project_name: 项目名称
        nodes: 节点列表
        edges: 边列表
        entry_point: 入口点
        mermaid_code: Mermaid图表代码
        risk_summary: 风险摘要
        upstream: 上游列表
        downstream: 下游列表
    
    Returns:
        Markdown报告字符串
    """
    groups = classify_nodes(nodes)
    
    lines = []
    lines.append(f"# {project_name} - 架构分析报告")
    lines.append("")
    
    # 概览
    lines.append("## 概览")
    lines.append(f"- 分析节点数: {len(nodes)}")
    lines.append(f"- 依赖关系数: {len(edges)}")
    lines.append(f"- 入口点: `{entry_point}`")
    if risk_summary:
        lines.append(f"- 风险摘要: {risk_summary}")
    lines.append("")
    
    # 架构图
    if mermaid_code:
        lines.append("## 架构图")
        lines.append("```mermaid")
        lines.append(mermaid_code)
        lines.append("```")
        lines.append("")
    
    # 层级分布
    lines.append("## 层级分布")
    for layer_name in LAYER_ORDER:
        layer_nodes = groups.get(layer_name, [])
        if not layer_nodes:
            continue
        label = LAYER_LABELS.get(layer_name, layer_name)
        lines.append(f"### {label} ({len(layer_nodes)}个)")
        lines.append("")
        lines.append("| 节点 | 文件路径 |")
        lines.append("|------|----------|")
        for node in layer_nodes:
            name = node.get("name", "")
            fp = node.get("filePath", node.get("file_path", ""))
            lines.append(f"| `{name}` | `{fp}` |")
        lines.append("")
    
    # 上下游
    if upstream:
        lines.append("## 上游调用者")
        for u in upstream[:20]:
            lines.append(f"- `{u}`")
        lines.append("")
    
    if downstream:
        lines.append("## 下游依赖")
        for d in downstream[:20]:
            lines.append(f"- `{d}`")
        lines.append("")
    
    return "\n".join(lines)
