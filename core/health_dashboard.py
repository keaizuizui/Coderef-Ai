# -*- coding: utf-8 -*-
"""
HealthDashboard v1.0 -- 项目健康仪表盘

面向非编程人员（老板、产品经理），聚合 CodeRef 所有分析结果，
生成一个自包含的 HTML 页面，一眼看懂项目健康状态。

数据来源:
  - PipeResult.findings: 审计发现列表
  - CodeKnowledgeGraph.get_stats(): 知识图谱统计

输出: coderef-report/health_dashboard_{timestamp}.html
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Optional

from .pipeline_runner import PipeResult, Finding, Tier


# ═══════════════════════════════════════════════════════════════════
# HTML 模板
# ═══════════════════════════════════════════════════════════════════

_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>项目健康仪表盘 - {project_name}</title>
<style>
/* ═══════════════════════════════════════════════════════════════════
   基础样式
   ═══════════════════════════════════════════════════════════════════ */
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", "PingFang SC",
                 "Microsoft YaHei", "Helvetica Neue", Arial, sans-serif;
    background: #0f1117; color: #e5e7eb; line-height: 1.6;
    min-height: 100vh;
}}
.container {{ max-width: 1400px; margin: 0 auto; padding: 24px; }}

/* ═══════════════════════════════════════════════════════════════════
   顶部标题栏
   ═══════════════════════════════════════════════════════════════════ */
.header {{
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 24px; padding: 20px 28px;
    background: linear-gradient(135deg, #1a1d2e 0%, #1e2130 100%);
    border-radius: 12px; border: 1px solid #2a2d3a;
}}
.header h1 {{ font-size: 24px; font-weight: 700; color: #f1f5f9; }}
.header .timestamp {{ font-size: 13px; color: #6b7280; }}

/* ═══════════════════════════════════════════════════════════════════
   概览卡片行
   ═══════════════════════════════════════════════════════════════════ */
.overview {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 24px; }}
.card {{
    background: #1a1d2e; border-radius: 10px; padding: 18px 20px;
    border: 1px solid #2a2d3a; transition: border-color 0.2s;
}}
.card:hover {{ border-color: #3b82f6; }}
.card .label {{ font-size: 12px; color: #6b7280; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; }}
.card .value {{ font-size: 28px; font-weight: 700; color: #f1f5f9; }}
.card .value.small {{ font-size: 18px; }}
.card .sub {{ font-size: 12px; color: #6b7280; margin-top: 4px; }}

/* 健康评分卡片特殊样式 */
.score-card {{ text-align: center; }}
.score-ring {{
    display: inline-block; position: relative; width: 100px; height: 100px;
}}
.score-ring svg {{ transform: rotate(-90deg); }}
.score-ring .bg {{ fill: none; stroke: #2a2d3a; stroke-width: 8; }}
.score-ring .fg {{ fill: none; stroke-width: 8; stroke-linecap: round; transition: stroke-dashoffset 0.8s ease; }}
.score-ring .txt {{
    position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%);
    font-size: 28px; font-weight: 800;
}}
.score-excellent {{ color: #10b981; }}
.score-good {{ color: #3b82f6; }}
.score-warning {{ color: #f59e0b; }}
.score-danger {{ color: #ef4444; }}

/* ═══════════════════════════════════════════════════════════════════
   三列布局
   ═══════════════════════════════════════════════════════════════════ */
.columns {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 16px; margin-bottom: 24px; }}
@media (max-width: 1100px) {{ .columns {{ grid-template-columns: 1fr; }} }}

.panel {{
    background: #1a1d2e; border-radius: 10px; border: 1px solid #2a2d3a;
    overflow: hidden;
}}
.panel-header {{
    padding: 14px 20px; border-bottom: 1px solid #2a2d3a;
    font-size: 14px; font-weight: 600; color: #d1d5db;
    display: flex; align-items: center; gap: 8px;
}}
.panel-body {{ padding: 16px 20px; }}

/* ═══════════════════════════════════════════════════════════════════
   工具进度条
   ═══════════════════════════════════════════════════════════════════ */
.tool-row {{ margin-bottom: 14px; }}
.tool-row:last-child {{ margin-bottom: 0; }}
.tool-label {{
    display: flex; justify-content: space-between; align-items: center;
    margin-bottom: 4px; font-size: 13px;
}}
.tool-name {{ color: #c9cdd4; font-weight: 500; }}
.tool-count {{ color: #6b7280; font-size: 12px; }}
.progress-bar {{
    height: 8px; background: #2a2d3a; border-radius: 4px; overflow: hidden;
    display: flex;
}}
.progress-bar .seg {{ height: 100%; transition: width 0.3s; }}
.seg-high {{ background: #ef4444; }}
.seg-medium {{ background: #f59e0b; }}
.seg-low {{ background: #9ca3af; }}

/* ═══════════════════════════════════════════════════════════════════
   CSS 饼图
   ═══════════════════════════════════════════════════════════════════ */
.pie-section {{ margin-bottom: 16px; }}
.pie-title {{ font-size: 13px; color: #9ca3af; margin-bottom: 10px; font-weight: 500; }}
.pie-container {{ display: flex; align-items: center; gap: 20px; }}
.pie-chart {{
    width: 120px; height: 120px; border-radius: 50%; flex-shrink: 0;
}}
.pie-legend {{ font-size: 12px; }}
.pie-legend-item {{ display: flex; align-items: center; gap: 6px; margin-bottom: 6px; }}
.pie-dot {{ width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0; }}
.pie-legend-name {{ color: #c9cdd4; }}
.pie-legend-count {{ color: #6b7280; margin-left: auto; }}

.kg-stats {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 16px; }}
.kg-stat {{
    background: #14171f; border-radius: 8px; padding: 12px; text-align: center;
}}
.kg-stat .val {{ font-size: 22px; font-weight: 700; color: #f1f5f9; }}
.kg-stat .lbl {{ font-size: 11px; color: #6b7280; margin-top: 2px; }}

/* ═══════════════════════════════════════════════════════════════════
   TOP 风险清单
   ═══════════════════════════════════════════════════════════════════ */
.risk-list {{ max-height: 420px; overflow-y: auto; }}
.risk-item {{
    padding: 10px 0; border-bottom: 1px solid #252836;
    display: flex; gap: 10px; align-items: flex-start;
}}
.risk-item:last-child {{ border-bottom: none; }}
.risk-severity {{
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 11px; font-weight: 600; white-space: nowrap; flex-shrink: 0;
}}
.sev-critical {{ background: #7f1d1d; color: #fca5a5; }}
.sev-high {{ background: #7f1d1d; color: #fca5a5; }}
.sev-medium {{ background: #78350f; color: #fcd34d; }}
.sev-low {{ background: #1f2937; color: #9ca3af; }}
.risk-info {{ flex: 1; min-width: 0; }}
.risk-title {{ font-size: 13px; color: #e5e7eb; font-weight: 500; word-break: break-all; }}
.risk-meta {{ font-size: 11px; color: #6b7280; margin-top: 2px; }}
.risk-file {{ font-family: "SF Mono", "Cascadia Code", Consolas, monospace; font-size: 11px; color: #6b7280; }}
.empty-state {{ text-align: center; color: #6b7280; padding: 40px 0; font-size: 14px; }}

/* ═══════════════════════════════════════════════════════════════════
   详细列表
   ═══════════════════════════════════════════════════════════════════ */
.detail-section {{ margin-bottom: 24px; }}
.detail-toggle {{
    width: 100%; padding: 14px 20px; background: #1a1d2e;
    border: 1px solid #2a2d3a; border-radius: 10px; color: #d1d5db;
    font-size: 14px; font-weight: 600; cursor: pointer; text-align: left;
    display: flex; justify-content: space-between; align-items: center;
    transition: border-color 0.2s;
}}
.detail-toggle:hover {{ border-color: #3b82f6; }}
.detail-toggle .arrow {{ font-size: 12px; transition: transform 0.3s; }}
.detail-toggle.open .arrow {{ transform: rotate(180deg); }}

.detail-content {{ display: none; margin-top: 0; }}
.detail-content.show {{ display: block; }}

.findings-table {{
    width: 100%; border-collapse: collapse; margin-top: 12px;
    border-radius: 10px; overflow: hidden; border: 1px solid #2a2d3a;
}}
.findings-table th {{
    background: #1e2130; padding: 10px 14px; font-size: 12px;
    font-weight: 600; color: #9ca3af; text-align: left; white-space: nowrap;
}}
.findings-table td {{
    padding: 10px 14px; font-size: 13px; border-top: 1px solid #252836;
    color: #c9cdd4; vertical-align: top;
}}
.findings-table tr:hover td {{ background: #1e2130; }}
.findings-table .row-high {{ border-left: 3px solid #ef4444; }}
.findings-table .row-medium {{ border-left: 3px solid #f59e0b; }}
.findings-table .row-low {{ border-left: 3px solid #9ca3af; }}
.tier-badge {{
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-size: 11px; font-weight: 600;
}}
.tier-high {{ background: #7f1d1d; color: #fca5a5; }}
.tier-medium {{ background: #78350f; color: #fcd34d; }}
.tier-low {{ background: #1f2937; color: #9ca3af; }}

.xval-tag {{
    display: inline-block; margin-left: 4px; padding: 1px 6px;
    border-radius: 3px; background: #312e81; color: #a5b4fc;
    font-size: 10px; font-weight: 600;
}}

/* ═══════════════════════════════════════════════════════════════════
   页脚
   ═══════════════════════════════════════════════════════════════════ */
.footer {{
    text-align: center; padding: 20px; color: #4b5563; font-size: 12px;
    border-top: 1px solid #1f2937; margin-top: 24px;
}}

/* ═══════════════════════════════════════════════════════════════════
   滚动条
   ═══════════════════════════════════════════════════════════════════ */
::-webkit-scrollbar {{ width: 6px; height: 6px; }}
::-webkit-scrollbar-track {{ background: #14171f; }}
::-webkit-scrollbar-thumb {{ background: #374151; border-radius: 3px; }}
::-webkit-scrollbar-thumb:hover {{ background: #4b5563; }}

/* ═══════════════════════════════════════════════════════════════════
   tier 分布条
   ═══════════════════════════════════════════════════════════════════ */
.tier-dist {{ display: flex; gap: 4px; margin-top: 8px; }}
.tier-dist .td-item {{
    flex: 1; text-align: center; padding: 6px 4px; border-radius: 6px;
    font-size: 11px;
}}
.td-high {{ background: #7f1d1d; color: #fca5a5; }}
.td-medium {{ background: #78350f; color: #fcd34d; }}
.td-low {{ background: #1f2937; color: #9ca3af; }}
.td-num {{ font-size: 18px; font-weight: 700; display: block; }}
</style>
</head>
<body>
<div class="container">

<!-- ═══════════════════════════════════════════════════════════════════
   顶部
   ═══════════════════════════════════════════════════════════════════ -->
<div class="header">
    <h1>项目健康仪表盘</h1>
    <span class="timestamp">分析时间: {build_time}</span>
</div>

<!-- ═══════════════════════════════════════════════════════════════════
   概览卡片
   ═══════════════════════════════════════════════════════════════════ -->
<div class="overview">
    <div class="card">
        <div class="label">项目名称</div>
        <div class="value small">{project_name}</div>
        <div class="sub">{project_path}</div>
    </div>
    <div class="card">
        <div class="label">文件总数</div>
        <div class="value">{total_files}</div>
        <div class="sub">共 {total_lines} 行代码</div>
    </div>
    <div class="card">
        <div class="label">发现总数</div>
        <div class="value">{total_findings}</div>
        <div class="tier-dist">
            {tier_dist_html}
        </div>
    </div>
    <div class="card score-card">
        <div class="label">健康评分</div>
        {score_html}
    </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════════
   三列布局
   ═══════════════════════════════════════════════════════════════════ -->
<div class="columns">
    <!-- 左列: 工具安全评分 -->
    <div class="panel">
        <div class="panel-header">按工具分类</div>
        <div class="panel-body">
            {tool_bars_html}
        </div>
    </div>

    <!-- 中列: 知识图谱 -->
    <div class="panel">
        <div class="panel-header">知识图谱</div>
        <div class="panel-body">
            {kg_html}
        </div>
    </div>

    <!-- 右列: TOP 风险 -->
    <div class="panel">
        <div class="panel-header">TOP 风险清单</div>
        <div class="panel-body">
            <div class="risk-list">
                {top_risks_html}
            </div>
        </div>
    </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════════
   详细发现列表
   ═══════════════════════════════════════════════════════════════════ -->
<div class="detail-section">
    <button class="detail-toggle" onclick="toggleDetail()">
        <span>详细发现列表（共 {total_findings} 条）</span>
        <span class="arrow">&#9660;</span>
    </button>
    <div class="detail-content" id="detailContent">
        <table class="findings-table">
            <thead>
                <tr>
                    <th>#</th>
                    <th>置信度</th>
                    <th>工具</th>
                    <th>分类</th>
                    <th>严重程度</th>
                    <th>文件</th>
                    <th>行号</th>
                    <th>描述</th>
                    <th>建议</th>
                </tr>
            </thead>
            <tbody>
                {detail_rows_html}
            </tbody>
        </table>
    </div>
</div>

<!-- ═══════════════════════════════════════════════════════════════════
   页脚
   ═══════════════════════════════════════════════════════════════════ -->
<div class="footer">
    CodeRef 项目健康仪表盘 &middot; 由 CodeRef AI 自动生成
</div>

</div>

<script>
function toggleDetail() {{
    var content = document.getElementById('detailContent');
    var btn = document.querySelector('.detail-toggle');
    content.classList.toggle('show');
    btn.classList.toggle('open');
}}
</script>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════
# HealthDashboard
# ═══════════════════════════════════════════════════════════════════

# 饼图颜色方案（节点类型 → 颜色）
_PIE_COLORS_NODE = [
    "#3b82f6", "#8b5cf6", "#ec4899", "#f59e0b", "#10b981",
    "#06b6d4", "#ef4444", "#84cc16", "#f97316", "#6366f1",
]
_PIE_COLORS_EDGE = [
    "#2563eb", "#7c3aed", "#db2777", "#d97706", "#059669",
    "#0891b2", "#dc2626", "#65a30d", "#ea580c", "#4f46e5",
]


class HealthDashboard:
    """项目健康仪表盘 —— 生成自包含 HTML 报告"""

    def __init__(self, project_path: str):
        self.project_path = os.path.abspath(project_path)

    # ─── 公共方法 ───

    def build(self, pipe_result: PipeResult, kg_stats: dict) -> str:
        """构建仪表盘 HTML 页面。

        Args:
            pipe_result: 管线运行结果
            kg_stats: 知识图谱统计信息 (get_stats() 返回值)

        Returns:
            生成的 HTML 文件绝对路径
        """
        score = self._calc_score(pipe_result.findings)
        html = self._render_html(pipe_result, kg_stats, score)

        # 输出到 coderef-report 目录
        out_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "coderef-report")
        os.makedirs(out_dir, exist_ok=True)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"health_dashboard_{timestamp}.html"
        filepath = os.path.join(out_dir, filename)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        return filepath

    def _calc_score(self, findings: List[Finding]) -> int:
        """计算健康评分 0-100。

        规则:
          - 基础分 100
          - HIGH: -5 分/条
          - MEDIUM: -1 分/条
          - LOW: -0.2 分/条
          - 最低 0 分
        """
        if not findings:
            return 100

        score = 100.0
        for f in findings:
            if f.tier == Tier.HIGH:
                score -= 5
            elif f.tier == Tier.MEDIUM:
                score -= 1
            elif f.tier == Tier.LOW:
                score -= 0.2

        return max(0, int(score))

    # ─── HTML 渲染 ───

    def _render_html(self, pr: PipeResult, kg_stats: dict, score: int) -> str:
        """渲染完整 HTML"""

        project_name = os.path.basename(self.project_path.rstrip(os.sep))
        build_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 按 tier 排序 findings
        tier_order = {Tier.HIGH: 0, Tier.MEDIUM: 1, Tier.LOW: 2}
        sorted_findings = sorted(pr.findings, key=lambda f: (
            tier_order.get(f.tier, 99), f.severity, f.file_path, f.line))

        # 各子模板
        tier_dist_html = self._render_tier_dist(pr.findings)
        score_html = self._render_score(score)
        tool_bars_html = self._render_tool_bars(pr.findings)
        kg_html = self._render_kg(kg_stats)
        top_risks_html = self._render_top_risks(pr.findings)
        detail_rows_html = self._render_detail_rows(sorted_findings)

        return _HTML_TEMPLATE.format(
            project_name=project_name,
            project_path=self.project_path,
            total_files=pr.total_files,
            total_lines=pr.total_lines,
            total_findings=len(pr.findings),
            build_time=build_time,
            tier_dist_html=tier_dist_html,
            score_html=score_html,
            tool_bars_html=tool_bars_html,
            kg_html=kg_html,
            top_risks_html=top_risks_html,
            detail_rows_html=detail_rows_html,
        )

    # ─── 子模板渲染 ───

    def _render_tier_dist(self, findings: List[Finding]) -> str:
        """渲染 tier 分布条"""
        h = sum(1 for f in findings if f.tier == Tier.HIGH)
        m = sum(1 for f in findings if f.tier == Tier.MEDIUM)
        lo = sum(1 for f in findings if f.tier == Tier.LOW)
        return (
            f'<div class="td-item td-high"><span class="td-num">{h}</span>HIGH</div>'
            f'<div class="td-item td-medium"><span class="td-num">{m}</span>MEDIUM</div>'
            f'<div class="td-item td-low"><span class="td-num">{lo}</span>LOW</div>'
        )

    def _render_score(self, score: int) -> str:
        """渲染健康评分环形图"""
        # 根据分数决定颜色
        if score >= 80:
            cls = "score-excellent"
        elif score >= 60:
            cls = "score-good"
        elif score >= 40:
            cls = "score-warning"
        else:
            cls = "score-danger"

        # SVG 环形图: r=42, circumference ≈ 2*pi*42 ≈ 263.89
        circumference = 263.89
        offset = circumference * (1 - score / 100.0)

        return f"""<div class="score-ring">
            <svg width="100" height="100" viewBox="0 0 100 100">
                <circle class="bg" cx="50" cy="50" r="42"/>
                <circle class="fg" cx="50" cy="50" r="42"
                    stroke-dasharray="{circumference:.2f}"
                    stroke-dashoffset="{offset:.2f}"
                    style="stroke: {self._score_color(score)}"/>
            </svg>
            <div class="txt {cls}">{score}</div>
        </div>
        <div class="sub" style="margin-top:8px">{self._score_label(score)}</div>"""

    @staticmethod
    def _score_color(score: int) -> str:
        if score >= 80:
            return "#10b981"
        elif score >= 60:
            return "#3b82f6"
        elif score >= 40:
            return "#f59e0b"
        return "#ef4444"

    @staticmethod
    def _score_label(score: int) -> str:
        if score >= 80:
            return "优秀"
        elif score >= 60:
            return "良好"
        elif score >= 40:
            return "需关注"
        return "风险较高"

    def _render_tool_bars(self, findings: List[Finding]) -> str:
        """渲染按工具分类的进度条"""
        if not findings:
            return '<div class="empty-state">暂无发现</div>'

        # 按 tool 聚合
        by_tool: Dict[str, Dict[str, int]] = {}
        for f in findings:
            t = f.tool or "unknown"
            if t not in by_tool:
                by_tool[t] = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
            by_tool[t][f.tier.value.upper()] += 1

        # 按总数降序
        tool_order = sorted(by_tool.items(),
                            key=lambda kv: sum(kv[1].values()), reverse=True)

        tool_names = {
            "gov": "治理审计", "td": "技术债务", "agent": "Agent 安全",
            "blind": "盲区检测", "integ": "完整性检查", "sca": "SCA 依赖",
            "junk": "冗余检测", "resgap": "资源缺口", "simp": "代码简化",
            "inn": "创新传播", "matu": "成熟度评估",
        }

        rows = []
        for tool, counts in tool_order:
            total = sum(counts.values())
            name = tool_names.get(tool, tool)
            h_pct = counts["HIGH"] / total * 100 if total else 0
            m_pct = counts["MEDIUM"] / total * 100 if total else 0
            l_pct = counts["LOW"] / total * 100 if total else 0

            rows.append(f"""<div class="tool-row">
                <div class="tool-label">
                    <span class="tool-name">{name}</span>
                    <span class="tool-count">{total} 条</span>
                </div>
                <div class="progress-bar">
                    <div class="seg seg-high" style="width:{h_pct:.1f}%"></div>
                    <div class="seg seg-medium" style="width:{m_pct:.1f}%"></div>
                    <div class="seg seg-low" style="width:{l_pct:.1f}%"></div>
                </div>
            </div>""")

        return "\n".join(rows)

    def _render_kg(self, kg_stats: dict) -> str:
        """渲染知识图谱概览"""
        if not kg_stats or "error" in kg_stats:
            return '<div class="empty-state">知识图谱数据不可用</div>'

        node_count = kg_stats.get("node_count", 0)
        edge_count = kg_stats.get("edge_count", 0)
        node_types = kg_stats.get("node_types", {})
        edge_types = kg_stats.get("edge_types", {})
        built_at = kg_stats.get("built_at", "")

        if node_count == 0:
            return '<div class="empty-state">知识图谱为空</div>'

        # 数字统计
        stats_html = f"""<div class="kg-stats">
            <div class="kg-stat"><div class="val">{node_count}</div><div class="lbl">节点</div></div>
            <div class="kg-stat"><div class="val">{edge_count}</div><div class="lbl">边</div></div>
        </div>"""

        # 节点类型饼图
        node_pie = self._render_pie(node_types, _PIE_COLORS_NODE, "节点类型分布")
        # 边类型饼图
        edge_pie = self._render_pie(edge_types, _PIE_COLORS_EDGE, "边类型分布")

        built_info = ""
        if built_at:
            built_info = f'<div style="font-size:11px;color:#6b7280;text-align:center;margin-top:8px">图谱构建: {built_at}</div>'

        return stats_html + node_pie + edge_pie + built_info

    @staticmethod
    def _render_pie(type_counts: dict, colors: list, title: str) -> str:
        """用 CSS conic-gradient 渲染饼图"""
        if not type_counts:
            return ""

        # 按数量降序
        sorted_types = sorted(type_counts.items(), key=lambda kv: kv[1], reverse=True)
        total = sum(v for _, v in sorted_types)

        # 构建 conic-gradient 字符串
        segments = []
        cumulative = 0.0
        legend_items = []

        # 中文类型名映射
        type_names = {
            "function": "函数", "method": "方法", "class": "类",
            "module": "模块", "config": "配置", "constant": "常量",
            "route": "路由", "ref": "引用",
            "CALLS": "调用", "CONTAINS": "包含", "IMPORTS": "导入",
            "INHERITS": "继承", "REFERENCES": "引用", "ROUTES_TO": "路由",
        }

        for i, (typ, count) in enumerate(sorted_types):
            pct = count / total * 100
            color = colors[i % len(colors)]
            segments.append(f"{color} {cumulative:.1f}% {cumulative + pct:.1f}%")
            cumulative += pct

            display_name = type_names.get(typ, typ)
            legend_items.append(
                f'<div class="pie-legend-item">'
                f'<span class="pie-dot" style="background:{color}"></span>'
                f'<span class="pie-legend-name">{display_name}</span>'
                f'<span class="pie-legend-count">{count}</span>'
                f'</div>'
            )

        pie_style = f"conic-gradient({', '.join(segments)})"

        return f"""<div class="pie-section">
            <div class="pie-title">{title}</div>
            <div class="pie-container">
                <div class="pie-chart" style="background:{pie_style}"></div>
                <div class="pie-legend">{"".join(legend_items)}</div>
            </div>
        </div>"""

    def _render_top_risks(self, findings: List[Finding]) -> str:
        """渲染 TOP 10 HIGH 发现"""
        high_findings = [f for f in findings if f.tier == Tier.HIGH]
        if not high_findings:
            return '<div class="empty-state">暂无 HIGH 风险</div>'

        top10 = high_findings[:10]
        rows = []
        for f in top10:
            sev_cls = f"sev-{f.severity}" if f.severity in (
                "critical", "high", "medium", "low") else "sev-medium"
            file_name = os.path.basename(f.file_path) if f.file_path else ""
            xval = ""
            if f.xval_by:
                xval = f' <span class="xval-tag">x{",".join(f.xval_by)}</span>'

            rows.append(f"""<div class="risk-item">
                <span class="risk-severity {sev_cls}">{f.severity}</span>
                <div class="risk-info">
                    <div class="risk-title">{self._escape_html(f.title[:80])}{xval}</div>
                    <div class="risk-file">{file_name}:{f.line}</div>
                </div>
            </div>""")

        return "\n".join(rows)

    def _render_detail_rows(self, findings: List[Finding]) -> str:
        """渲染详细发现表格行"""
        if not findings:
            return ('<tr><td colspan="9" style="text-align:center;color:#6b7280;'
                    'padding:40px">暂无发现</td></tr>')

        rows = []
        for i, f in enumerate(findings, 1):
            tier_cls = f"tier-{f.tier.value}"
            row_cls = f"row-{f.tier.value}"
            tier_label = {"high": "HIGH", "medium": "MEDIUM", "low": "LOW"}.get(
                f.tier.value, f.tier.value.upper())

            xval = ""
            if f.xval_by:
                xval = f' <span class="xval-tag">x{",".join(f.xval_by)}</span>'

            file_name = os.path.basename(f.file_path) if f.file_path else f.file_path

            rows.append(f"""<tr class="{row_cls}">
                <td>{i}</td>
                <td><span class="tier-badge {tier_cls}">{tier_label}</span></td>
                <td>{f.tool}</td>
                <td>{f.category}</td>
                <td>{f.severity}</td>
                <td style="font-family:monospace;font-size:11px">{self._escape_html(file_name)}</td>
                <td>{f.line}</td>
                <td>{self._escape_html(f.title[:100])}{xval}</td>
                <td style="font-size:11px;color:#9ca3af">{self._escape_html(f.suggestion[:120])}</td>
            </tr>""")

        return "\n".join(rows)

    @staticmethod
    def _escape_html(text: str) -> str:
        """转义 HTML 特殊字符"""
        if not text:
            return ""
        return (text.replace("&", "&amp;")
                    .replace("<", "&lt;")
                    .replace(">", "&gt;")
                    .replace('"', "&quot;"))