# -*- coding: utf-8 -*-
"""
Pipeline Runner v2.0 — 三模式管线

  coderef_audit        → 11 审计工具 一次产出
  coderef_architecture  → 架构分析图谱
  coderef_docs          → 项目文档探查

All modes share: single AST scan + checkpoint resume.
"""

import os, sys, json, time, hashlib, traceback, importlib
from datetime import datetime
from loguru import logger
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from enum import Enum

class Tier(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

@dataclass
class Finding:
    id: str; tool: str; category: str; severity: str = "medium"
    file_path: str = ""; line: int = 0; title: str = ""
    detail: str = ""; suggestion: str = ""
    tier: Tier = Tier.LOW
    xval_by: List[str] = field(default_factory=list)

@dataclass
class PipeResult:
    project_path: str; total_files: int = 0; total_lines: int = 0
    findings: List[Finding] = field(default_factory=list)
    report: str = ""; errors: List[str] = field(default_factory=list)
    elapsed: float = 0.0; report_path: str = ""

class Pipe:

    def __init__(self):
        self._t0 = 0.0

    @staticmethod
    def _phash(p: str) -> str:
        return hashlib.md5(p.encode()).hexdigest()[:12]

    @staticmethod
    def _cdir() -> str:
        d = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "cache", "pipeline")
        os.makedirs(d, exist_ok=True)
        return d

    # ─── checkpoint ───

    def _ckpt(self, p: str) -> str:
        return os.path.join(self._cdir(), f"{self._phash(p)}.ckpt.json")

    def _save(self, p: str, done: List[str]):
        try:
            with open(self._ckpt(p), "w", encoding="utf-8") as f:
                json.dump({"done": done, "ts": datetime.now().isoformat()}, f)
        except: pass

    def _load(self, p: str) -> set:
        try:
            cp = self._ckpt(p)
            return set(json.load(open(cp)).get("done", [])) if os.path.exists(cp) else set()
        except: return set()

    # ─── AI 白名单（编程 AI 补充意见持久化）───

    @staticmethod
    def _whitelist_path(project_path: str) -> str:
        h = Pipe._phash(project_path)
        return os.path.join(Pipe._cdir(), f"wl_{h}.json")

    @staticmethod
    def whitelist_add(project_path: str, entries: List[dict]) -> int:
        """AI 可调用：添加白名单条目。返回新增数量。

        每个 entry 可含：file（匹配 file_path 子串）、rule（匹配 title 子串）、
        category（匹配 category 子串）。三者 AND 逻辑。
        """
        path = Pipe._whitelist_path(project_path)
        existing = []
        if os.path.exists(path):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    existing = json.load(f)
            except: pass
        added = 0
        for e in entries:
            entry = {k: str(v).lower() for k, v in e.items() if v}
            if entry and entry not in existing:
                existing.append(entry)
                added += 1
        with open(path, "w", encoding="utf-8") as f:
            json.dump(existing, f, ensure_ascii=False, indent=1)
        return added

    @staticmethod
    def whitelist_list(project_path: str) -> list:
        """查看当前白名单"""
        path = Pipe._whitelist_path(project_path)
        if os.path.exists(path):
            try:
                return json.load(open(path, "r", encoding="utf-8"))
            except: pass
        return []

    @staticmethod
    def whitelist_clear(project_path: str) -> int:
        """清空白名单，返回被删除的条目数"""
        path = Pipe._whitelist_path(project_path)
        if os.path.exists(path):
            n = len(json.load(open(path, "r", encoding="utf-8")))
            os.remove(path)
            return n
        return 0

    def _load_whitelist(self, project_path: str) -> list:
        """加载 AI 白名单（供 _denoise 使用）"""
        return self.whitelist_list(project_path)

    # ─── 核心模块规则管理（AI 可追加入口文件名/核心模块名/阈值）───

    @staticmethod
    def core_rules_get(project_path: str) -> dict:
        """查看当前核心模块判定规则"""
        from core.wiki_generator import WikiGenerator
        return WikiGenerator.get_core_rules(project_path)

    @staticmethod
    def core_rules_set(project_path: str, rules: dict) -> dict:
        """设置核心模块判定规则

        rules 可含:
          - entry_files: ["main.py", "app.py", ...]  入口文件名列表
          - core_names: ["洞察工具", "shared", ...]  强制核心模块名
          - min_files: 10                             文件数阈值
        未指定的字段保持默认值。
        """
        from core.wiki_generator import WikiGenerator
        current = WikiGenerator.get_core_rules(project_path)
        if "entry_files" in rules:
            current["entry_files"] = rules["entry_files"]
        if "core_names" in rules:
            current["core_names"] = rules["core_names"]
        if "min_files" in rules:
            current["min_files"] = rules["min_files"]
        ok = WikiGenerator.save_core_rules(project_path, current)
        return {"saved": ok, "rules": current} if ok else {"error": "保存失败"}

    @staticmethod
    def core_rules_reset(project_path: str) -> dict:
        """重置为核心模块判定默认规则"""
        from core.wiki_generator import WikiGenerator
        default = {
            "entry_files": list(WikiGenerator.DEFAULT_ENTRY_FILES),
            "core_names": [],
            "min_files": WikiGenerator.DEFAULT_MIN_FILES,
        }
        ok = WikiGenerator.save_core_rules(project_path, default)
        return {"saved": ok, "rules": default} if ok else {"error": "保存失败"}

    # ─── shared AST ───

    def _scan(self, p: str) -> tuple:
        from core.code_analyzer import CodeAnalyzer
        a = CodeAnalyzer().analyze_project(p)
        return (getattr(a, "total_files", 0) or 0, getattr(a, "total_lines", 0) or 0, a)

    # ─── knowledge graph ───

    def _build_kg(self, project_path: str, analysis) -> dict:
        """构建知识图谱（异步，不影响主流程）"""
        try:
            from core.code_knowledge_graph import build_knowledge_graph
            from core.ast_parser import AstParser
            gx = os.path.join(project_path, ".gitnexus", "csv")
            if not os.path.isdir(gx):
                gx = None

            # 批量 AST 解析 Python 文件
            ast_results = {}
            py_files = [cf for cf in getattr(analysis, "files", [])
                        if getattr(cf, "file_path", "").endswith(".py")]
            parsed_count = 0
            for cf in py_files:
                file_path = cf.file_path
                try:
                    ar = AstParser().parse(file_path)
                    if ar:
                        ast_results[file_path] = ar
                        parsed_count += 1
                except Exception:
                    pass

            total_calls = sum(
                len(getattr(ar, "calls", [])) for ar in ast_results.values())
            total_assigns = sum(
                len(getattr(ar, "assignments", [])) for ar in ast_results.values())
            logger.info(
                f"[KG] AST 解析: {parsed_count}/{len(py_files)} 个 Python 文件, "
                f"提取 {total_calls} 条 CALLS 边, {total_assigns} 个 Config/Constant 节点"
            )

            kg = build_knowledge_graph(
                project_path, analysis=analysis,
                ast_results=ast_results, gitnexus_dir=gx)
            return kg.get_stats()
        except Exception as e:
            return {"error": str(e)}

    # ═══════════════════════════════════
    # 三大管线
    # ═══════════════════════════════════

    def audit(self, project_path: str, output_dir: str = None,
              resume: bool = False) -> PipeResult:
        """安全审计管线：11 工具"""
        self._t0 = time.time()
        r = PipeResult(project_path=project_path)
        d = self._load(project_path) if resume else set()
        out = output_dir or os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "coderef-report")

        try:
            tf, tl, analysis = self._scan(project_path)
            r.total_files, r.total_lines = tf, tl

            # 构建知识图谱（持久化项目记忆）
            kg_stats = self._build_kg(project_path, analysis)

            self._gov(project_path, r, d)
            self._agent(project_path, r, d)
            self._sca(project_path, r, d)
            self._td(project_path, r, d)
            self._integ(project_path, r, d)
            self._blind(project_path, r, d)
            self._inn(project_path, r, d)
            self._junk(project_path, r, d)
            self._resgap(project_path, r, d)
            self._simp(project_path, r, d)
            self._matu(project_path, r, d)

            self._xval(r)
            self._denoise(r)
            r.report = self._fmt(r, "审计报告")

            os.makedirs(out, exist_ok=True)
            fn = f"coderef_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            r.report_path = os.path.join(out, fn)
            with open(r.report_path, "w", encoding="utf-8") as f:
                f.write(r.report)

            # 生成健康仪表盘
            try:
                from core.health_dashboard import HealthDashboard
                dashboard = HealthDashboard(project_path)
                dashboard_path = dashboard.build(r, kg_stats)
                r.dashboard_path = dashboard_path
            except Exception as e:
                r.errors.append(f"dashboard: {e}")

            if os.path.exists(self._ckpt(project_path)):
                os.remove(self._ckpt(project_path))
        except Exception as e:
            r.errors.append(str(e))

        r.elapsed = round(time.time() - self._t0, 1)
        return r

    def architecture(self, project_path: str, output_dir: str = None,
                     resume: bool = False) -> PipeResult:
        """架构图管线：GitNexus + Workflow"""
        self._t0 = time.time()
        r = PipeResult(project_path=project_path)
        out = output_dir or os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "coderef-report")

        try:
            tf, tl, analysis = self._scan(project_path)
            r.total_files, r.total_lines = tf, tl

            # 构建知识图谱
            self._build_kg(project_path, analysis)

            self._workflow(project_path, r)

            r.report = self._fmt(r, "架构分析报告")
            os.makedirs(out, exist_ok=True)
            fn = f"coderef_arch_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
            r.report_path = os.path.join(out, fn)
            with open(r.report_path, "w", encoding="utf-8") as f:
                f.write(r.report)
        except Exception as e:
            r.errors.append(str(e))

        r.elapsed = round(time.time() - self._t0, 1)
        return r

    def docs(self, project_path: str, output_dir: str = None,
             resume: bool = False) -> PipeResult:
        """文档探查管线：Wiki"""
        self._t0 = time.time()
        r = PipeResult(project_path=project_path)
        d = self._load(project_path) if resume else set()

        try:
            tf, tl, analysis = self._scan(project_path)
            r.total_files, r.total_lines = tf, tl

            # 构建知识图谱
            self._build_kg(project_path, analysis)

            self._wiki(project_path, r, d)

            r.report = self._fmt(r, "文档探查报告")
            os.makedirs(output_dir or os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "coderef-report"), exist_ok=True)
        except Exception as e:
            r.errors.append(str(e))

        r.elapsed = round(time.time() - self._t0, 1)
        return r

    # ═══════════════════════════════════
    # 检测器
    # ═══════════════════════════════════

    def _gov(self, p: str, r: PipeResult, done: set):
        if "gov" in done: return
        try:
            importlib.invalidate_caches()
            pc = os.path.join(os.path.dirname(__file__), "__pycache__")
            if os.path.exists(pc):
                for f in os.listdir(pc):
                    if "governance_audit" in f or "shared_filter" in f:
                        os.remove(os.path.join(pc, f))
            from core import governance_audit as g, shared_filter as sf
            importlib.reload(sf); importlib.reload(g)
            a = g.GovernanceAuditor(); a.audit(p)
            ro = getattr(a, "report", None)
            if ro:
                for v in ro.violations:
                    r.findings.append(Finding(id=f"gov-{len(r.findings)}", tool="gov",
                        category=v.category, severity=v.severity,
                        file_path=v.file_path, line=v.line_number,
                        title=v.rule_name, detail=v.detail,
                        suggestion=v.suggestion, tier=Tier.MEDIUM))
            done.add("gov"); self._save(p, list(done))
        except Exception as e: r.errors.append(f"gov: {e}")

    def _agent(self, p: str, r: PipeResult, done: set):
        if "agent" in done: return
        try:
            from core.agent_security_auditor import AgentSecurityAuditor
            AgentSecurityAuditor().audit(p)
            done.add("agent"); self._save(p, list(done))
        except Exception as e: r.errors.append(f"agent: {e}")

    def _sca(self, p: str, r: PipeResult, done: set):
        if "sca" in done: return
        try:
            from core.sca_checker import SCAChecker
            SCAChecker().scan(p)
            done.add("sca"); self._save(p, list(done))
        except Exception as e: r.errors.append(f"sca: {e}")

    def _td(self, p: str, r: PipeResult, done: set):
        if "td" in done: return
        try:
            from core.tech_debt_detector import TechDebtDetector
            d = TechDebtDetector(); d.detect(p)
            for x in getattr(d, "debts", []):
                r.findings.append(Finding(id=f"td-{len(r.findings)}", tool="td",
                    category=getattr(x,"category",""), severity=getattr(x,"severity","medium"),
                    file_path=getattr(x,"file_path",""), line=getattr(x,"line",0),
                    title=getattr(x,"description",""), detail=getattr(x,"detail",getattr(x,"description","")),
                    suggestion=getattr(x,"suggestion",""), tier=Tier.MEDIUM))
            done.add("td"); self._save(p, list(done))
        except Exception as e: r.errors.append(f"td: {e}")

    def _integ(self, p: str, r: PipeResult, done: set):
        if "integ" in done: return
        try:
            from core.integrity_checker import IntegrityChecker
            IntegrityChecker().check(p)
            done.add("integ"); self._save(p, list(done))
        except Exception as e: r.errors.append(f"integ: {e}")

    def _blind(self, p: str, r: PipeResult, done: set):
        if "blind" in done: return
        try:
            from core.blind_spot_detector import BlindSpotDetector
            d = BlindSpotDetector(); d.detect(p)
            for s in getattr(d, "spots", []):
                r.findings.append(Finding(id=f"bs-{len(r.findings)}", tool="blind",
                    category=getattr(s,"category",""), file_path=getattr(s,"file_path",""),
                    title=getattr(s,"item",""), detail=getattr(s,"detail",""), tier=Tier.MEDIUM))
            done.add("blind"); self._save(p, list(done))
        except Exception as e: r.errors.append(f"blind: {e}")

    def _inn(self, p: str, r: PipeResult, done: set):
        if "inn" in done: return
        try:
            from core.innovation_propagation_detector import InnovationPropagationDetector
            InnovationPropagationDetector().detect(p, use_llm=True)
            done.add("inn"); self._save(p, list(done))
        except Exception as e: r.errors.append(f"inn: {e}")

    def _junk(self, p: str, r: PipeResult, done: set):
        if "junk" in done: return
        try:
            from core.junk_detector import JunkDetector
            JunkDetector().detect(p)
            done.add("junk"); self._save(p, list(done))
        except Exception as e: r.errors.append(f"junk: {e}")

    def _resgap(self, p: str, r: PipeResult, done: set):
        if "resgap" in done: return
        try:
            from core.resource_gap_detector import ResourceGapDetector
            ResourceGapDetector().detect(p)
            done.add("resgap"); self._save(p, list(done))
        except Exception as e: r.errors.append(f"resgap: {e}")

    def _simp(self, p: str, r: PipeResult, done: set):
        if "simp" in done: return
        try:
            from core.code_simplifier import CodeSimplifier
            CodeSimplifier().analyze(p)
            done.add("simp"); self._save(p, list(done))
        except Exception as e: r.errors.append(f"simp: {e}")

    def _matu(self, p: str, r: PipeResult, done: set):
        if "matu" in done: return
        try:
            from core.project_maturity_checker import ProjectMaturityChecker
            ProjectMaturityChecker().check(p)
            done.add("matu"); self._save(p, list(done))
        except Exception as e: r.errors.append(f"matu: {e}")

    def _workflow(self, p: str, r: PipeResult):
        try:
            from core.workflow_graph import WorkflowGraph
            html = WorkflowGraph().generate(project_path=p)
            r.report_path = html
        except Exception as e: r.errors.append(f"workflow: {e}")

    def _wiki(self, p: str, r: PipeResult, done: set):
        if "wiki" in done: return
        try:
            from core.wiki_generator import WikiGenerator
            wo = os.path.join(os.path.dirname(os.path.dirname(
                os.path.abspath(__file__))), "txt")
            WikiGenerator().generate(p, output_dir=wo, wiki_style="comprehensive", include_subprojects=True)
            done.add("wiki"); self._save(p, list(done))
        except Exception as e: r.errors.append(f"wiki: {e}")

    # ═══════════════════════════════════
    # 交叉验证 + 格式化
    # ═══════════════════════════════════

    def _xval(self, r: PipeResult):
        """多工具命中同一位置 → HIGH"""
        by = {}
        for f in r.findings:
            k = (f.file_path, f.line, f.category)
            by.setdefault(k, []).append(f)
        for fl in by.values():
            tools = list(set(f.tool for f in fl))
            if len(tools) >= 2:
                for f in fl:
                    f.xval_by = [t for t in tools if t != f.tool]
                    f.tier = Tier.HIGH

    # ═══════════════════════════════════
    # 自动降噪（零 LLM / 零白名单）
    # ═══════════════════════════════════

    # 降噪规则库：每个 rule 检测是否为已知误报模式
    NOISE_RULES = {
        # MD5 for project hashing, not crypto — IRON-SEC-10 in governance
        "md5_for_hashing": {
            "tools": {"gov"},
            "category_keywords": {"security"},
            "title_keywords": {"iron-sec-10", "弱加密", "不安全的加密"},
            "action": "suppress",
            "reason": "MD5 用于项目路径哈希，非安全场景",
        },
        # exec/eval in developer tooling
        "exec_in_tooling": {
            "tools": {"gov"},
            "category_keywords": {"security"},
            "title_keywords": {"代码注入", "exec(", "eval(", "subprocess"},
            "action": "downgrade",
            "reason": "开发工具中动态导入非安全漏洞",
        },
        # Magic URL/path in config files
        "config_url": {
            "tools": {"td"},
            "category_keywords": {"magic_value"},
            "file_keywords": {"config", "settings", ".yaml", ".toml", ".ini"},
            "title_keywords": {"http://", "https://", "localhost", "DB_"},
            "action": "suppress",
            "reason": "配置文件中的 URL/路径是正常配置",
        },
        # Blind spot "missing dependency" where module is sibling dir
        "sibling_import": {
            "tools": {"blind"},
            "category_keywords": {"missing_dependency"},
            "action": "downgrade",
            "reason": "同项目内跨目录 import 被误判为缺失依赖",
        },
        # doc_blindspot flood — 每个目录都说"没有 docs/"
        "doc_blindspot_flood": {
            "tools": {"blind"},
            "category_keywords": {"doc_blindspot"},
            "action": "downgrade",
            "reason": "目录缺少 docs/ 是普遍现象非真实盲区",
        },
    }

    # 爆发式重复阈值：同 tool + category > N → 合并
    BURST_THRESHOLD = 8
    # 邻近行合并窗口：同 file + tool + category 的行号差 < N → 合并
    ADJACENT_LINE_WINDOW = 5

    def _denoise(self, r: PipeResult):
        """自动降噪：AI白名单 + 规则去重 + 抑制 + 降级"""
        if not r.findings:
            return

        suppressed = 0
        downgraded = 0
        wl_suppressed = 0
        kept = []

        # 加载 AI 白名单
        wl = self._load_whitelist(r.project_path)

        # ── 第一轮：AI 白名单 + 规则匹配 ──
        for f in r.findings:
            if self._match_whitelist(f, wl):
                wl_suppressed += 1
                continue
            matched_rule = self._match_noise_rule(f)
            if matched_rule:
                action = matched_rule["action"]
                if action == "suppress":
                    suppressed += 1
                    continue
                elif action == "downgrade":
                    f.tier = Tier.LOW
                    downgraded += 1
            kept.append(f)

        r.findings = kept

        # ── 第二轮：邻近行合并（同 file + tool + category) ──
        r.findings = self._dedup_adjacent(r.findings)

        # ── 第三轮：爆发式合并（同 tool + category > 阈值 → 保留 1 条 + 摘要）──
        r.findings = self._burst_merge(r.findings)

        # 记录降噪统计
        if suppressed or downgraded or wl_suppressed:
            setattr(r, 'noise_suppressed', suppressed)
            setattr(r, 'noise_downgraded', downgraded)
            setattr(r, 'wl_suppressed', wl_suppressed)

    @staticmethod
    def _match_whitelist(f: Finding, wl: list) -> bool:
        """f 是否匹配白名单条目（AND 逻辑）"""
        fl = f.file_path.lower()
        tl = f.title.lower()
        cl = f.category.lower()
        for entry in wl:
            if entry.get("file") and entry["file"] not in fl:
                continue
            if entry.get("rule") and entry["rule"] not in tl:
                continue
            if entry.get("category") and entry["category"] not in cl:
                continue
            return True
        return False

    def _match_noise_rule(self, f: Finding) -> dict:
        """f 是否匹配任一降噪规则"""
        title_lower = f.title.lower()
        cat_lower = f.category.lower()
        file_lower = os.path.basename(f.file_path).lower() if f.file_path else ""

        for name, rule in self.NOISE_RULES.items():
            # 工具过滤
            if rule.get("tools") and f.tool not in rule["tools"]:
                continue
            # 分类关键词
            if rule.get("category_keywords"):
                if not any(kw in cat_lower for kw in rule["category_keywords"]):
                    continue
            # 标题关键词
            if rule.get("title_keywords"):
                if not any(kw in title_lower for kw in rule["title_keywords"]):
                    continue
            # 文件关键词
            if rule.get("file_keywords"):
                if not any(kw in file_lower for kw in rule["file_keywords"]):
                    continue
            # 目录关键词
            if rule.get("dir_keywords") and f.file_path:
                dir_lower = os.path.dirname(f.file_path).lower()
                if not any(kw in dir_lower for kw in rule["dir_keywords"]):
                    continue
            return rule
        return {}

    @staticmethod
    def _dedup_adjacent(findings: List[Finding]) -> List[Finding]:
        """同文件 + 同规则 + 邻行 → 合并为 1 条"""
        if not findings:
            return findings
        # 按 (file, tool, category) 分组排序
        findings.sort(key=lambda f: (
            f.file_path, f.tool, f.category, f.line
        ))
        result = []
        for f in findings:
            if result:
                prev = result[-1]
                if (f.file_path == prev.file_path
                        and f.tool == prev.tool
                        and f.category == prev.category
                        and f.line - prev.line <= Pipe.ADJACENT_LINE_WINDOW):
                    # 合并
                    prev.title = f"{prev.title} (等多行)"
                    prev.line = max(prev.line, f.line)
                    if f.detail and f.detail not in prev.detail:
                        prev.detail += " | " + f.detail
                    continue
            result.append(f)
        return result

    @staticmethod
    def _burst_merge(findings: List[Finding]) -> List[Finding]:
        """同 tool + category 超过阈值 → 保留 1 条 + 统计摘要"""
        by_key = {}
        for f in findings:
            k = (f.tool, f.category)
            by_key.setdefault(k, []).append(f)

        result = []
        for k, group in by_key.items():
            if len(group) <= Pipe.BURST_THRESHOLD:
                result.extend(group)
            else:
                # 保留第 1 条 + 摘要
                first = group[0]
                first.title = f"[共 {len(group)} 条] {first.title}"
                first.detail = f"此项在 {len(set(f.file_path for f in group))} 个文件中出现 {len(group)} 次，为爆发式重复，合并显示。"
                first.tier = Tier.LOW
                result.append(first)
        return result

    def _fmt(self, r: PipeResult, title: str) -> str:
        h = [f for f in r.findings if f.tier == Tier.HIGH]
        m = [f for f in r.findings if f.tier == Tier.MEDIUM]
        l = [f for f in r.findings if f.tier == Tier.LOW]
        lines = [
            f"# CodeRef {title}",
            f"项目: `{r.project_path}` | 文件: {r.total_files} | 行: {r.total_lines} | {r.elapsed}s",
            f"时间: {datetime.now().strftime('%Y-%m-%d %H:%M')}",
            "", "## 置信度",
            f"| 🔴 HIGH | 🟡 MEDIUM | ⚪ LOW |",
            f"|----------|------------|---------|",
            f"| {len(h)} | {len(m)} | {len(l)} |",
            "",
        ]
        ns = getattr(r, 'noise_suppressed', 0)
        nd = getattr(r, 'noise_downgraded', 0)
        wl = getattr(r, 'wl_suppressed', 0)
        if ns or nd or wl:
            parts = []
            if ns: parts.append(f"抑制 {ns} 条已知误报")
            if nd: parts.append(f"降级 {nd} 条低置信度")
            if wl: parts.append(f"白名单过滤 {wl} 条")
            lines.append(f"> 🤖 自动降噪: {'; '.join(parts)}")
            lines.append("")
        if r.errors:
            lines.append("## ⚠️ 异常"); 
            for e in r.errors: lines.append(f"- {e}")
            lines.append("")
        if h:
            lines.append("## 🔴 HIGH（多工具交叉验证）");
            lines.append("|工具|分类|程度|文件|描述|");
            lines.append("|---|---|---|---|---|")
            for f in h[:30]:
                xv = f" ×{','.join(f.xval_by)}" if f.xval_by else ""
                lines.append(f"|{f.tool}|{f.category}|{f.severity}|{f.file_path}:{f.line}|{f.title[:60]}{xv}|")
            lines.append("")
        if m:
            lines.append("## 🟡 MEDIUM");
            lines.append("|工具|分类|程度|描述|")
            for f in m[:20]: lines.append(f"|{f.tool}|{f.category}|{f.severity}|{f.title[:80]}|")
            lines.append("")
        lines.append(f"---\n{r.report_path or ''}")
        return "\n".join(lines)

    # ═══════════════════════════════════
    # 知识图谱查询（供 MCP Server 调用）
    # ═══════════════════════════════════

    @staticmethod
    def kg_query(project_path: str, query_type: str, **kwargs) -> dict:
        """查询项目知识图谱。

        query_type:
          - stats: 获取统计信息
          - entity: 按名称搜索实体 (name, type?)
          - callers: 查询调用者 (func_name)
          - callees: 查询被调用者 (func_name)
          - impact: 修改影响分析 (file_path)
          - relations: 查询节点关系 (node_id)
          - file_entities: 查询文件实体 (file_path)
          - search: 全文搜索 (keyword)
          - call_graph: 调用链子图 (func_name, depth?)
        """
        from core.code_knowledge_graph import load_knowledge_graph
        kg = load_knowledge_graph(project_path)
        if not kg:
            return {"error": "知识图谱不存在，请先运行 coderef_audit/coderef_docs/coderef_architecture"}

        try:
            if query_type == "stats":
                return kg.get_stats()
            elif query_type == "entity":
                r = kg.query_entity(kwargs.get("name", ""), kwargs.get("type"))
                return {"nodes": [n.to_dict() for n in r.nodes], "total": r.total}
            elif query_type == "callers":
                r = kg.query_callers(kwargs.get("func_name", ""))
                return {"nodes": [n.to_dict() for n in r.nodes], "total": r.total}
            elif query_type == "callees":
                r = kg.query_callees(kwargs.get("func_name", ""))
                return {"nodes": [n.to_dict() for n in r.nodes], "total": r.total}
            elif query_type == "impact":
                r = kg.query_impact(kwargs.get("file_path", ""))
                return {"nodes": [n.to_dict() for n in r.nodes], "total": r.total}
            elif query_type == "relations":
                r = kg.query_relations(kwargs.get("node_id", ""))
                return {"nodes": [n.to_dict() for n in r.nodes],
                        "edges": [e.to_dict() for e in r.edges], "total": r.total}
            elif query_type == "file_entities":
                r = kg.query_file_entities(kwargs.get("file_path", ""))
                return {"nodes": [n.to_dict() for n in r.nodes], "total": r.total}
            elif query_type == "search":
                r = kg.search(kwargs.get("keyword", ""), kwargs.get("limit", 30))
                return {"nodes": [n.to_dict() for n in r.nodes], "total": r.total}
            elif query_type == "call_graph":
                r = kg.get_call_graph(kwargs.get("func_name", ""), kwargs.get("depth", 2))
                return {"nodes": [n.to_dict() for n in r.nodes],
                        "edges": [e.to_dict() for e in r.edges], "total": r.total}
            else:
                return {"error": f"未知查询类型: {query_type}，支持: stats/entity/callers/callees/impact/relations/file_entities/search/call_graph"}
        finally:
            kg.close()
