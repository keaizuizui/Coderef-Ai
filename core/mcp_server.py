# -*- coding: utf-8 -*-
"""
CodeRef MCP Server v3.0 — 四功能
  coderef_audit        → 11 审计工具 一键产出
  coderef_architecture  → 架构分析图谱
  coderef_docs          → 项目文档探查
  coderef_query         → 知识图谱查询
  coderef_task_status   → 后台任务查询
"""

import json, sys, os, logging, traceback, threading, uuid
from datetime import datetime
from typing import Dict, List, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

logging.basicConfig(level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stderr)])
logger = logging.getLogger("coderef")


class Server:

    def __init__(self):
        self._tools = [
            {
                "name": "coderef_whitelist",
                "description": (
                    "管理 AI 白名单和核心模块判定规则。\n"
                    "action=add/list/clear → 误报白名单管理；\n"
                    "action=core_rules_get → 查看当前核心模块判定规则；\n"
                    "action=core_rules_set → 设置核心模块规则（entry_files入口文件名列表/core_names强制核心模块名/min_files文件数阈值）；\n"
                    "action=core_rules_reset → 重置为默认规则。\n"
                    "你审查完报告后，把确认无误的误报条目写入白名单。发现 Wiki 漏了核心模块时，用 core_rules_set 追加。"
                ),
                "inputSchema": {"type": "object", "properties": {
                    "project_path": {"type": "string", "description": "目标项目路径"},
                    "action": {"type": "string", "enum": ["add", "list", "clear", "core_rules_get", "core_rules_set", "core_rules_reset"], "default": "add"},
                    "entries": {
                        "type": "array", "items": {"type": "object",
                            "properties": {
                                "file": {"type": "string", "description": "文件路径子串"},
                                "rule": {"type": "string", "description": "规则名/标题子串"},
                                "category": {"type": "string", "description": "分类子串"},
                            }
                        },
                        "description": "要加入白名单的条目 (action=add 时必填)"
                    },
                    "core_rules": {
                        "type": "object",
                        "properties": {
                            "entry_files": {"type": "array", "items": {"type": "string"}, "description": "入口文件名列表，如 [\"main.py\",\"app.py\",\"server.py\"]"},
                            "core_names": {"type": "array", "items": {"type": "string"}, "description": "强制核心模块名列表，如 [\"洞察工具\",\"shared\"]"},
                            "min_files": {"type": "integer", "description": "文件数阈值（>=此值自动视为核心模块）"},
                        },
                        "description": "核心模块规则 (action=core_rules_set 时必填)"
                    },
                }, "required": ["project_path"]},
            },
            {
                "name": "coderef_audit",
                "description": (
                    "全维度代码审计 = 治理审计 + Agent安全 + 依赖扫描(CVE) + 技术债务 + "
                    "完整性检查 + 盲区检测 + 创新传播 + 垃圾文件 + 资源遗漏 + 代码精简 + 项目成熟度。\n"
                    "11 个工具一次产出，交叉验证自动分级(HIGH/MEDIUM/LOW)。\n"
                    "解决 AI 自查幻觉：多独立工具互验。\n"
                    "支持 background=True 后台执行。"
                ),
                "inputSchema": {"type": "object", "properties": {
                    "project_path": {"type": "string", "description": "目标项目路径"},
                    "output_dir": {"type": "string", "description": "报告输出目录（默认 coderef-report/）"},
                    "background": {"type": "boolean", "description": "后台执行", "default": True},
                }, "required": ["project_path"]},
            },
            {
                "name": "coderef_architecture",
                "description": (
                    "架构分析图谱 = 代码结构分析 + 交互式模块画布(HTML)。\n"
                    "含 GitNexus 索引增强，展示模块交互关系、调用链。\n"
                    "用于发现零散重复代码、模块不统一等问题。"
                ),
                "inputSchema": {"type": "object", "properties": {
                    "project_path": {"type": "string", "description": "目标项目路径"},
                }, "required": ["project_path"]},
            },
            {
                "name": "coderef_docs",
                "description": (
                    "项目文档探查 = 结构化 Wiki 生成(README/架构/安装/使用/API)。\n"
                    "三级管线：AST元数据(全量)→LLM归纳→编校验证(无幻觉)。\n"
                    "自动发现子项目并生成独立 Wiki。\n"
                    "支持 background=True（推荐，生成耗时 3-20 分钟）。"
                ),
                "inputSchema": {"type": "object", "properties": {
                    "project_path": {"type": "string", "description": "目标项目路径"},
                    "output_dir": {"type": "string", "description": "输出目录（默认 txt/）"},
                    "wiki_style": {"type": "string", "enum": ["comprehensive","reference","tutorial","plain"], "default": "comprehensive"},
                    "include_subprojects": {"type": "boolean", "default": True},
                    "background": {"type": "boolean", "default": True},
                }, "required": ["project_path"]},
            },
            {
                "name": "coderef_task_status",
                "description": "查询后台任务状态",
                "inputSchema": {"type": "object", "properties": {
                    "task_id": {"type": "string"},
                }},
            },
            {
                "name": "coderef_query",
                "description": (
                    "查询项目知识图谱（结构化项目记忆层）。\n"
                    "在运行 coderef_audit/coderef_docs/coderef_architecture 后自动构建。\n"
                    "query_type 支持:\n"
                    "  stats      → 图谱统计（节点数、边数、类型分布）\n"
                    "  entity     → 按名称搜索实体 (需 name；可选 type: function/class/module/config/constant)\n"
                    "  callers    → 查询谁调用了这个函数 (需 func_name)\n"
                    "  callees    → 查询这个函数调用了谁 (需 func_name)\n"
                    "  impact     → 修改影响分析：修改此文件会影响哪些模块 (需 file_path)\n"
                    "  relations  → 查询节点所有关系 (需 node_id)\n"
                    "  file_entities → 查询文件中的所有实体 (需 file_path)\n"
                    "  search     → 全文搜索 (需 keyword)\n"
                    "  call_graph → 调用链子图 (需 func_name；可选 depth 默认2)\n"
                    "用于编程 AI 替代 grep/读文件：精准查询项目结构，节省 10-100 倍 token。"
                ),
                "inputSchema": {"type": "object", "properties": {
                    "project_path": {"type": "string", "description": "目标项目路径"},
                    "query_type": {"type": "string", "enum": ["stats","entity","callers","callees","impact","relations","file_entities","search","call_graph"]},
                    "name": {"type": "string", "description": "实体名称（query_type=entity 时必填）"},
                    "func_name": {"type": "string", "description": "函数名（query_type=callers/callees/call_graph 时必填）"},
                    "file_path": {"type": "string", "description": "文件路径（query_type=impact/file_entities 时必填）"},
                    "node_id": {"type": "string", "description": "节点ID（query_type=relations 时必填）"},
                    "keyword": {"type": "string", "description": "搜索关键词（query_type=search 时必填）"},
                    "depth": {"type": "integer", "description": "调用链深度（call_graph 默认2）", "default": 2},
                    "type": {"type": "string", "description": "实体类型过滤（query_type=entity 时可选）"},
                    "limit": {"type": "integer", "description": "返回数量上限（search 默认30）", "default": 30},
                }, "required": ["project_path", "query_type"]},
            },
        ]
        self._tasks: Dict[str, Any] = {}

    # ─── request ───

    def _handle(self, req: Dict) -> Dict:
        m, rid = req.get("method",""), req.get("id")
        if m == "initialize":
            return {"jsonrpc":"2.0","id":rid,"result":{
                "protocolVersion":"2024-11-05","capabilities":{"tools":{}},
                "serverInfo":{"name":"coderef-ai","version":"3.1.0"}}}
        if m == "notifications/initialized": return None
        if m == "tools/list":
            return {"jsonrpc":"2.0","id":rid,"result":{"tools":self._tools}}
        if m == "tools/call":
            return self._call(rid, req.get("params",{}))
        return {"jsonrpc":"2.0","id":rid,"error":{"code":-32601,"message":f"未知: {m}"}}

    def _call(self, rid, params):
        n, a = params.get("name",""), params.get("arguments",{})
        try:
            if n == "coderef_task_status":
                return self._ok(rid, self._tsk(a))
            if n == "coderef_query":
                return self._ok(rid, self._query(a))
            if n == "coderef_architecture":
                return self._ok(rid, self._arch(a))
            if n == "coderef_whitelist":
                return self._ok(rid, self._wl(a))
            bg = a.get("background", n == "coderef_docs")
            if bg:
                tid = str(uuid.uuid4())[:8]; rc = {}
                t = threading.Thread(target=lambda: self._bg(rc, n, a), daemon=True)
                t.start(); self._tasks[tid] = {"thread":t,"result":rc,"tool":n}
                logger.info(f"后台: {tid} {n}")
                return self._ok(rid, json.dumps({"status":"running","task_id":tid,
                    "message":f"已启动。coderef_task_status(task_id='{tid}') 查询进度"}, ensure_ascii=False))
            return self._ok(rid, self._run(n, a))
        except Exception as e:
            return {"jsonrpc":"2.0","id":rid,"error":{"code":-32000,"message":str(e)}}

    def _bg(self, rc, n, a):
        try: rc["result"] = self._run(n, a)
        except Exception as e: rc["error"] = str(e); rc["tb"] = traceback.format_exc()

    def _run(self, n, a) -> str:
        from core.pipeline_runner import Pipe
        p, o = a["project_path"], a.get("output_dir")
        logger.info(f"[{n}] {p}")
        if n == "coderef_audit":
            r = Pipe().audit(p, output_dir=o)
        elif n == "coderef_docs":
            r = Pipe().docs(p, output_dir=o)
        else: return "未知"
        logger.info(f"[{n}] 完成: {r.elapsed}s")
        return r.report

    def _arch(self, a) -> str:
        from core.pipeline_runner import Pipe
        r = Pipe().architecture(a["project_path"])
        return r.report or f"架构图: {r.report_path}"

    def _wl(self, a) -> str:
        from core.pipeline_runner import Pipe
        act = a.get("action", "add")
        pp = a["project_path"]
        if act == "list":
            wl = Pipe.whitelist_list(pp)
            return json.dumps({"count": len(wl), "entries": wl}, ensure_ascii=False)
        elif act == "clear":
            n = Pipe.whitelist_clear(pp)
            return json.dumps({"cleared": n}, ensure_ascii=False)
        elif act == "core_rules_get":
            return json.dumps(Pipe.core_rules_get(pp), ensure_ascii=False)
        elif act == "core_rules_set":
            rules = a.get("core_rules", {})
            if not rules:
                return json.dumps({"error": "core_rules 不能为空"})
            return json.dumps(Pipe.core_rules_set(pp, rules), ensure_ascii=False)
        elif act == "core_rules_reset":
            return json.dumps(Pipe.core_rules_reset(pp), ensure_ascii=False)
        else:  # add
            entries = a.get("entries", [])
            if not entries:
                return json.dumps({"error": "entries 不能为空"})
            n = Pipe.whitelist_add(pp, entries)
            return json.dumps({"added": n, "total": len(Pipe.whitelist_list(pp))}, ensure_ascii=False)

    def _tsk(self, a) -> str:
        tid = a.get("task_id","")
        if not tid: return json.dumps({"tasks":list(self._tasks.keys())})
        t = self._tasks.get(tid)
        if not t: return json.dumps({"error":f"不存在: {tid}"})
        if t["thread"].is_alive(): return json.dumps({"status":"running","task_id":tid})
        rc = t["result"]
        if "error" in rc: return json.dumps({"status":"error","task_id":tid,"error":rc["error"]})
        r = rc.get("result",""); del self._tasks[tid]
        return json.dumps({"status":"completed","task_id":tid,"content":r}, ensure_ascii=False)

    def _query(self, a) -> str:
        from core.pipeline_runner import Pipe
        qt = a.get("query_type", "stats")
        pp = a["project_path"]
        kwargs = {k: v for k, v in a.items()
                  if k not in ("project_path", "query_type") and v}
        result = Pipe.kg_query(pp, qt, **kwargs)
        return json.dumps(result, ensure_ascii=False)

    @staticmethod
    def _ok(rid, text):
        return {"jsonrpc":"2.0","id":rid,"result":{"content":[{"type":"text","text":text}]}}

    def run(self):
        # 强制 stdout 为 UTF-8，解决 Windows 下中文乱码
        import io
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8')
        else:
            sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
        logger.info("CodeRef MCP v3.0 (audit|arch|docs) 启动")
        for line in sys.stdin:
            if not (line := line.strip()): continue
            try:
                req = json.loads(line)
                resp = self._handle(req)
                if resp is not None:
                    sys.stdout.write(json.dumps(resp, ensure_ascii=False)+"\n")
                    sys.stdout.flush()
            except json.JSONDecodeError: pass
            except Exception as e:
                sys.stdout.write(json.dumps({"jsonrpc":"2.0","id":None,
                    "error":{"code":-32000,"message":str(e)}}, ensure_ascii=False)+"\n")
                sys.stdout.flush()

def main(): Server().run()
if __name__ == "__main__": main()
