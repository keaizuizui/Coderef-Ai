# -*- coding: utf-8 -*-
"""
CodeKnowledgeGraph v1.0 —— 持久化项目知识图谱

为编程 AI 提供结构化、可检索的项目记忆层。
SQLite 存储：节点（函数/类/模块/配置/常量/路由）+ 边（CALLS/IMPORTS/CONTAINS/INHERITS/REFERENCES/ROUTES_TO）

数据源：
  1. CodeAnalyzer.analyze_project() → CodeFile（函数/类/导入）
  2. AstParser.parse() → AstFileResult（调用关系/赋值/配置）
  3. GitNexus CSV → relations/community/process（调用链/集群/执行流）

存储路径：cache/kg/{project_md5}.db
"""

import os, sys, json, hashlib, sqlite3, csv, time
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any

from loguru import logger


# ═══════════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════════

@dataclass
class KGNode:
    """知识图谱节点"""
    id: str
    type: str          # function / class / method / module / config / constant / route
    name: str
    file_path: str = ""
    start_line: int = 0
    end_line: int = 0
    props: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "type": self.type, "name": self.name,
            "file_path": self.file_path, "start_line": self.start_line,
            "end_line": self.end_line, "props": self.props
        }


@dataclass
class KGEdge:
    """知识图谱边"""
    source: str
    target: str
    type: str         # CALLS / IMPORTS / CONTAINS / INHERITS / REFERENCES / ROUTES_TO
    props: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"source": self.source, "target": self.target,
                "type": self.type, "props": self.props}


@dataclass
class KGQueryResult:
    """知识图谱查询结果"""
    nodes: List[KGNode] = field(default_factory=list)
    edges: List[KGEdge] = field(default_factory=list)
    total: int = 0
    query_type: str = ""


# ═══════════════════════════════════════════════════════════════════
# 知识图谱引擎
# ═══════════════════════════════════════════════════════════════════

class CodeKnowledgeGraph:
    """持久化项目知识图谱"""

    SCHEMA_VERSION = 1

    def __init__(self, project_path: str):
        self.project_path = os.path.abspath(project_path)
        self._phash = hashlib.md5(self.project_path.encode()).hexdigest()[:12]
        self._db_path = self._make_db_path()
        self._conn: Optional[sqlite3.Connection] = None

    # ─── 路径 ───

    @staticmethod
    def _kg_dir() -> str:
        d = os.path.join(os.path.dirname(os.path.dirname(
            os.path.abspath(__file__))), "cache", "kg")
        os.makedirs(d, exist_ok=True)
        return d

    def _make_db_path(self) -> str:
        return os.path.join(self._kg_dir(), f"{self._phash}.db")

    @property
    def db_path(self) -> str:
        return self._db_path

    # ─── 连接 ───

    def _connect(self):
        if self._conn is None:
            self._conn = sqlite3.connect(self._db_path)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")

    def close(self):
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self):
        self._connect()
        return self

    def __exit__(self, *args):
        self.close()

    # ─── 建表 ───

    def _init_schema(self):
        self._connect()
        self._conn.executescript("""
            CREATE TABLE IF NOT EXISTS nodes (
                id TEXT PRIMARY KEY,
                type TEXT NOT NULL,
                name TEXT NOT NULL,
                file_path TEXT DEFAULT '',
                start_line INTEGER DEFAULT 0,
                end_line INTEGER DEFAULT 0,
                props TEXT DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_nodes_type ON nodes(type);
            CREATE INDEX IF NOT EXISTS idx_nodes_name ON nodes(name);
            CREATE INDEX IF NOT EXISTS idx_nodes_file ON nodes(file_path);

            CREATE TABLE IF NOT EXISTS edges (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                source TEXT NOT NULL,
                target TEXT NOT NULL,
                type TEXT NOT NULL,
                props TEXT DEFAULT '{}'
            );
            CREATE INDEX IF NOT EXISTS idx_edges_source ON edges(source);
            CREATE INDEX IF NOT EXISTS idx_edges_target ON edges(target);
            CREATE INDEX IF NOT EXISTS idx_edges_type ON edges(type);

            CREATE TABLE IF NOT EXISTS meta (
                key TEXT PRIMARY KEY,
                value TEXT DEFAULT ''
            );
        """)
        self._conn.commit()

    # ─── 是否存在 / 是否过期 ───

    def exists(self) -> bool:
        return os.path.exists(self._db_path)

    def is_stale(self, max_age_hours: int = 24) -> bool:
        """检查知识图谱是否过期（超过 max_age_hours 小时）"""
        if not self.exists():
            return True
        try:
            self._connect()
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key='built_at'").fetchone()
            if row:
                built_at = float(row[0])
                return (time.time() - built_at) > max_age_hours * 3600
        except: pass
        return True

    def get_built_at(self) -> Optional[str]:
        """获取构建时间"""
        if not self.exists():
            return None
        try:
            self._connect()
            row = self._conn.execute(
                "SELECT value FROM meta WHERE key='built_at'").fetchone()
            if row:
                return datetime.fromtimestamp(float(row[0])).strftime("%Y-%m-%d %H:%M:%S")
        except: pass
        return None

    # ═══════════════════════════════════════════════════════════════════
    # 构建
    # ═══════════════════════════════════════════════════════════════════

    def build(self, analysis=None, ast_results=None, gitnexus_dir=None) -> dict:
        """
        构建知识图谱。

        Args:
            analysis: CodeAnalyzer.analyze_project() 返回值（ProjectAnalysis）
            ast_results: AstParser 批量解析结果 Dict[str, AstFileResult]
            gitnexus_dir: .gitnexus/csv/ 目录路径

        Returns:
            {"nodes": N, "edges": M, "errors": [...]}
        """
        self._init_schema()
        self._clear()
        stats = {"nodes": 0, "edges": 0, "errors": []}

        try:
            if analysis:
                self._build_from_analysis(analysis, stats)
            if ast_results:
                self._build_from_ast(ast_results, stats)
            if gitnexus_dir and os.path.isdir(gitnexus_dir):
                self._build_from_gitnexus(gitnexus_dir, stats)
        except Exception as e:
            stats["errors"].append(str(e))
            logger.error(f"[KG] 构建失败: {e}")

        self._set_meta("built_at", str(time.time()))
        self._set_meta("project_path", self.project_path)
        self._set_meta("schema_version", str(self.SCHEMA_VERSION))
        self._conn.commit()
        logger.info(f"[KG] 构建完成: {stats['nodes']} 节点, {stats['edges']} 边")
        return stats

    def _clear(self):
        self._conn.execute("DELETE FROM nodes")
        self._conn.execute("DELETE FROM edges")
        self._conn.execute("DELETE FROM meta")

    def _set_meta(self, key: str, value: str):
        self._conn.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", (key, value))

    # ─── 从 CodeAnalyzer 构建 ───

    def _build_from_analysis(self, analysis, stats: dict):
        """从 CodeAnalyzer.analyze_project() 的 ProjectAnalysis 构建节点"""
        n = 0
        for cf in getattr(analysis, "files", []):
            rel = getattr(cf, "file_path", "")
            if not rel:
                continue

            # 模块节点
            module_name = os.path.splitext(os.path.basename(rel))[0]
            module_id = f"mod:{module_name}"
            self._upsert_node(KGNode(
                id=module_id, type="module", name=module_name,
                file_path=rel, props={"language": getattr(cf, "language", "")}))
            n += 1

            # 函数节点
            for func in getattr(cf, "functions", []):
                fid = f"func:{module_name}:{func.name}"
                self._upsert_node(KGNode(
                    id=fid, type="function", name=func.name,
                    file_path=rel,
                    start_line=getattr(func, "start_line", 0),
                    end_line=getattr(func, "end_line", 0),
                    props={"params": getattr(func, "parameters", []),
                           "doc": (getattr(func, "docstring", "") or "")[:200],
                           "return_type": getattr(func, "return_type", "") or ""}))
                n += 1
                # CONTAINS 边
                self._upsert_edge(KGEdge(source=module_id, target=fid, type="CONTAINS"))

            # 类节点
            for cls in getattr(cf, "classes", []):
                cid = f"class:{module_name}:{cls.name}"
                self._upsert_node(KGNode(
                    id=cid, type="class", name=cls.name,
                    file_path=rel,
                    start_line=getattr(cls, "start_line", 0),
                    end_line=getattr(cls, "end_line", 0),
                    props={"bases": getattr(cls, "base_classes", []),
                           "doc": (getattr(cls, "docstring", "") or "")[:200]}))
                n += 1
                self._upsert_edge(KGEdge(source=module_id, target=cid, type="CONTAINS"))

                # 方法节点
                for m in getattr(cls, "methods", []):
                    mid = f"method:{module_name}:{cls.name}.{m.name}"
                    self._upsert_node(KGNode(
                        id=mid, type="method", name=f"{cls.name}.{m.name}",
                        file_path=rel,
                        start_line=getattr(m, "start_line", 0),
                        end_line=getattr(m, "end_line", 0),
                        props={"params": getattr(m, "parameters", []),
                               "doc": (getattr(m, "docstring", "") or "")[:200]}))
                    n += 1
                    self._upsert_edge(KGEdge(source=cid, target=mid, type="CONTAINS"))

                # 继承边
                for base in getattr(cls, "base_classes", []):
                    base_id = f"class:{base}"  # 可能跨模块
                    self._upsert_edge(KGEdge(source=cid, target=base_id, type="INHERITS"))

            # 导入边
            for imp in getattr(cf, "imports", []):
                target_mod = f"mod:{imp.split('.')[0]}"
                self._upsert_edge(KGEdge(
                    source=module_id, target=target_mod, type="IMPORTS",
                    props={"full": imp}))

        stats["nodes"] += n
        stats["edges"] += n  # 每个节点至少一条 CONTAINS 边

    # ─── 从 AstParser 构建 ───

    def _build_from_ast(self, ast_results: dict, stats: dict):
        """从 AstParser 批量解析结果构建调用关系和配置节点"""
        n = 0
        for file_path, ar in ast_results.items():
            module_name = os.path.splitext(os.path.basename(file_path))[0]
            rel = file_path

            # 调用关系 → CALLS 边
            for call in getattr(ar, "calls", []):
                caller_module = module_name
                # 尝试找到调用所在的函数
                caller_id = self._find_containing_node(rel, call.line)
                if not caller_id:
                    caller_id = f"mod:{caller_module}"

                # 被调用者
                callee_name = call.func_name.split(".")[-1]
                callee_id = self._find_node_by_name(callee_name)
                if callee_id:
                    self._upsert_edge(KGEdge(
                        source=caller_id, target=callee_id, type="CALLS",
                        props={"line": call.line, "full_name": call.func_name}))
                    n += 1

            # 赋值语句 → Config / Constant 节点
            for assign in getattr(ar, "assignments", []):
                cat = assign.category
                if cat in ("constant", "config", "hardcoded"):
                    node_type = "config" if cat in ("config", "hardcoded") else "constant"
                    aid = f"{node_type}:{module_name}:{assign.target}"
                    self._upsert_node(KGNode(
                        id=aid, type=node_type, name=assign.target,
                        file_path=rel, start_line=assign.line,
                        props={"value": assign.value_repr[:200],
                               "category": cat}))
                    n += 1

                    # REFERENCES 边（从所在函数引用此配置/常量）
                    container = self._find_containing_node(rel, assign.line)
                    if container:
                        self._upsert_edge(KGEdge(
                            source=container, target=aid, type="REFERENCES"))
                        n += 1

        stats["nodes"] += n

    # ─── 从 GitNexus CSV 构建 ───

    def _build_from_gitnexus(self, csv_dir: str, stats: dict):
        """从 GitNexus CSV 加载 relations 和 community"""
        n = 0

        # relations.csv
        rel_path = os.path.join(csv_dir, "relations.csv")
        if os.path.exists(rel_path):
            try:
                with open(rel_path, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        src = row.get("from", "")
                        tgt = row.get("to", "")
                        rtype = row.get("type", "")
                        if src and tgt:
                            # GitNexus 的 ID 可能含路径，我们尝试匹配
                            src_id = self._find_or_create_ref(src)
                            tgt_id = self._find_or_create_ref(tgt)
                            self._upsert_edge(KGEdge(
                                source=src_id, target=tgt_id, type=rtype,
                                props={"confidence": row.get("confidence", ""),
                                       "reason": row.get("reason", "")}))
                            n += 1
            except Exception as e:
                stats["errors"].append(f"GitNexus relations: {e}")

        # community.csv → 更新节点 props
        comm_path = os.path.join(csv_dir, "community.csv")
        if os.path.exists(comm_path):
            try:
                with open(comm_path, "r", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        label = row.get("label", "")
                        cohesion = row.get("cohesion", "")
                        if label:
                            # 更新所有匹配节点的 community 属性
                            self._conn.execute(
                                "UPDATE nodes SET props = json_set(props, '$.community', ?) "
                                "WHERE name = ? OR file_path LIKE ?",
                                (label, label, f"%{label}%"))
            except Exception as e:
                stats["errors"].append(f"GitNexus community: {e}")

        stats["edges"] += n

    # ═══════════════════════════════════════════════════════════════════
    # 查询
    # ═══════════════════════════════════════════════════════════════════

    def _row_to_node(self, row) -> KGNode:
        return KGNode(
            id=row["id"], type=row["type"], name=row["name"],
            file_path=row["file_path"] or "",
            start_line=row["start_line"] or 0,
            end_line=row["end_line"] or 0,
            props=json.loads(row["props"] or "{}"))

    def _row_to_edge(self, row) -> KGEdge:
        return KGEdge(
            source=row["source"], target=row["target"],
            type=row["type"],
            props=json.loads(row["props"] or "{}"))

    def _upsert_node(self, node: KGNode):
        self._conn.execute(
            """INSERT OR REPLACE INTO nodes(id,type,name,file_path,start_line,end_line,props)
               VALUES(?,?,?,?,?,?,?)""",
            (node.id, node.type, node.name, node.file_path,
             node.start_line, node.end_line, json.dumps(node.props, ensure_ascii=False)))

    def _upsert_edge(self, edge: KGEdge):
        self._conn.execute(
            """INSERT OR IGNORE INTO edges(source,target,type,props)
               VALUES(?,?,?,?)""",
            (edge.source, edge.target, edge.type,
             json.dumps(edge.props, ensure_ascii=False)))

    def _find_node_by_name(self, name: str) -> Optional[str]:
        row = self._conn.execute(
            "SELECT id FROM nodes WHERE name=? LIMIT 1", (name,)).fetchone()
        return row["id"] if row else None

    def _find_containing_node(self, file_path: str, line: int) -> Optional[str]:
        """找到包含指定行号的函数/方法/类节点"""
        row = self._conn.execute(
            """SELECT id FROM nodes
               WHERE file_path=? AND start_line <= ? AND end_line >= ?
               AND type IN ('function','method','class')
               ORDER BY (end_line - start_line) ASC LIMIT 1""",
            (file_path, line, line)).fetchone()
        return row["id"] if row else None

    def _find_or_create_ref(self, name: str) -> str:
        """查找或创建引用节点（用于 GitNexus 关系）"""
        existing = self._find_node_by_name(name)
        if existing:
            return existing
        nid = f"ref:{name}"
        self._upsert_node(KGNode(id=nid, type="ref", name=name))
        return nid

    # ─── 公共查询 API ───

    def query_entity(self, name: str, entity_type: str = None) -> KGQueryResult:
        """按名称查询实体"""
        self._connect()
        sql = "SELECT * FROM nodes WHERE name LIKE ?"
        params = [f"%{name}%"]
        if entity_type:
            sql += " AND type = ?"
            params.append(entity_type)
        rows = self._conn.execute(sql + " LIMIT 50", params).fetchall()
        nodes = [self._row_to_node(r) for r in rows]
        return KGQueryResult(nodes=nodes, total=len(nodes), query_type="entity")

    def query_callers(self, func_name: str) -> KGQueryResult:
        """查询调用者：谁调用了这个函数"""
        self._connect()
        target = self._find_node_by_name(func_name)
        if not target:
            # 模糊匹配
            row = self._conn.execute(
                "SELECT id FROM nodes WHERE name LIKE ? LIMIT 1",
                (f"%{func_name}%",)).fetchone()
            if not row:
                return KGQueryResult(total=0, query_type="callers")
            target = row["id"]

        # 反向追踪 CALLS 边
        rows = self._conn.execute(
            """SELECT n.* FROM nodes n
               JOIN edges e ON e.source = n.id
               WHERE e.target = ? AND e.type = 'CALLS'
               LIMIT 50""", (target,)).fetchall()
        nodes = [self._row_to_node(r) for r in rows]
        return KGQueryResult(nodes=nodes, total=len(nodes), query_type="callers")

    def query_callees(self, func_name: str) -> KGQueryResult:
        """查询被调用者：这个函数调用了谁"""
        self._connect()
        source = self._find_node_by_name(func_name)
        if not source:
            row = self._conn.execute(
                "SELECT id FROM nodes WHERE name LIKE ? LIMIT 1",
                (f"%{func_name}%",)).fetchone()
            if not row:
                return KGQueryResult(total=0, query_type="callees")
            source = row["id"]

        rows = self._conn.execute(
            """SELECT n.* FROM nodes n
               JOIN edges e ON e.target = n.id
               WHERE e.source = ? AND e.type = 'CALLS'
               LIMIT 50""", (source,)).fetchall()
        nodes = [self._row_to_node(r) for r in rows]
        return KGQueryResult(nodes=nodes, total=len(nodes), query_type="callees")

    def query_impact(self, file_path: str) -> KGQueryResult:
        """修改影响分析：修改某个文件会影响哪些模块"""
        self._connect()
        # 找到文件中的所有节点
        nodes = self._conn.execute(
            "SELECT id FROM nodes WHERE file_path LIKE ?",
            (f"%{file_path}%",)).fetchall()
        if not nodes:
            return KGQueryResult(total=0, query_type="impact")

        node_ids = [n["id"] for n in nodes]

        # 正向追踪：谁导入了这个模块？
        affected = set()
        for nid in node_ids:
            # 查找所有引用此节点的边
            refs = self._conn.execute(
                """SELECT DISTINCT e.source FROM edges e
                   WHERE e.target = ? AND e.type IN ('CALLS','IMPORTS','REFERENCES')""",
                (nid,)).fetchall()
            for r in refs:
                affected.add(r["source"])

        # 加载受影响节点
        if affected:
            placeholders = ",".join("?" * len(affected))
            rows = self._conn.execute(
                f"SELECT * FROM nodes WHERE id IN ({placeholders}) LIMIT 50",
                list(affected)).fetchall()
            result_nodes = [self._row_to_node(r) for r in rows]
        else:
            result_nodes = []

        return KGQueryResult(
            nodes=result_nodes, total=len(result_nodes), query_type="impact")

    def query_relations(self, node_id: str) -> KGQueryResult:
        """查询节点的所有关系"""
        self._connect()
        edges = []
        rows = self._conn.execute(
            "SELECT * FROM edges WHERE source=? OR target=? LIMIT 100",
            (node_id, node_id)).fetchall()
        edges = [self._row_to_edge(r) for r in rows]

        # 收集相关节点
        node_ids = set()
        for e in edges:
            node_ids.add(e.source)
            node_ids.add(e.target)

        nodes = []
        if node_ids:
            placeholders = ",".join("?" * len(node_ids))
            rows = self._conn.execute(
                f"SELECT * FROM nodes WHERE id IN ({placeholders})",
                list(node_ids)).fetchall()
            nodes = [self._row_to_node(r) for r in rows]

        return KGQueryResult(
            nodes=nodes, edges=edges, total=len(edges), query_type="relations")

    def query_file_entities(self, file_path: str) -> KGQueryResult:
        """查询文件中的所有实体"""
        self._connect()
        rows = self._conn.execute(
            "SELECT * FROM nodes WHERE file_path LIKE ? ORDER BY start_line LIMIT 100",
            (f"%{file_path}%",)).fetchall()
        nodes = [self._row_to_node(r) for r in rows]
        return KGQueryResult(nodes=nodes, total=len(nodes), query_type="file_entities")

    def get_stats(self) -> dict:
        """获取知识图谱统计信息"""
        self._connect()
        node_count = self._conn.execute("SELECT COUNT(*) as c FROM nodes").fetchone()["c"]
        edge_count = self._conn.execute("SELECT COUNT(*) as c FROM edges").fetchone()["c"]

        type_counts = {}
        for row in self._conn.execute(
                "SELECT type, COUNT(*) as c FROM nodes GROUP BY type").fetchall():
            type_counts[row["type"]] = row["c"]

        edge_type_counts = {}
        for row in self._conn.execute(
                "SELECT type, COUNT(*) as c FROM edges GROUP BY type").fetchall():
            edge_type_counts[row["type"]] = row["c"]

        built_at = self.get_built_at()

        return {
            "node_count": node_count,
            "edge_count": edge_count,
            "node_types": type_counts,
            "edge_types": edge_type_counts,
            "built_at": built_at,
            "project_path": self.project_path,
            "db_path": self._db_path,
        }

    def search(self, keyword: str, limit: int = 30) -> KGQueryResult:
        """全文搜索：名称、文件路径、docstring"""
        self._connect()
        pattern = f"%{keyword}%"
        rows = self._conn.execute(
            """SELECT * FROM nodes
               WHERE name LIKE ? OR file_path LIKE ? OR props LIKE ?
               LIMIT ?""",
            (pattern, pattern, pattern, limit)).fetchall()
        nodes = [self._row_to_node(r) for r in rows]
        return KGQueryResult(nodes=nodes, total=len(nodes), query_type="search")

    def get_call_graph(self, func_name: str, depth: int = 2) -> KGQueryResult:
        """获取调用链子图（BFS 遍历指定深度）"""
        self._connect()
        start = self._find_node_by_name(func_name)
        if not start:
            row = self._conn.execute(
                "SELECT id FROM nodes WHERE name LIKE ? LIMIT 1",
                (f"%{func_name}%",)).fetchone()
            if not row:
                return KGQueryResult(total=0, query_type="call_graph")
            start = row["id"]

        visited_nodes = {start}
        visited_edges = set()
        frontier = {start}

        for _ in range(depth):
            next_frontier = set()
            for nid in frontier:
                rows = self._conn.execute(
                    "SELECT * FROM edges WHERE (source=? OR target=?) AND type='CALLS'",
                    (nid, nid)).fetchall()
                for r in rows:
                    e = self._row_to_edge(r)
                    ek = (e.source, e.target, e.type)
                    if ek not in visited_edges:
                        visited_edges.add(ek)
                        visited_nodes.add(e.source)
                        visited_nodes.add(e.target)
                        if e.source == nid:
                            next_frontier.add(e.target)
                        else:
                            next_frontier.add(e.source)
            frontier = next_frontier
            if not frontier:
                break

        # 加载节点
        nodes = []
        if visited_nodes:
            placeholders = ",".join("?" * len(visited_nodes))
            rows = self._conn.execute(
                f"SELECT * FROM nodes WHERE id IN ({placeholders})",
                list(visited_nodes)).fetchall()
            nodes = [self._row_to_node(r) for r in rows]

        # 加载边
        edges = []
        for ek in visited_edges:
            edges.append(KGEdge(source=ek[0], target=ek[1], type=ek[2]))

        return KGQueryResult(
            nodes=nodes, edges=edges, total=len(edges), query_type="call_graph")


# ═══════════════════════════════════════════════════════════════════
# 便捷函数
# ═══════════════════════════════════════════════════════════════════

def build_knowledge_graph(project_path: str,
                          analysis=None,
                          ast_results=None,
                          gitnexus_dir=None) -> CodeKnowledgeGraph:
    """构建并返回知识图谱实例"""
    kg = CodeKnowledgeGraph(project_path)
    kg.build(analysis=analysis, ast_results=ast_results, gitnexus_dir=gitnexus_dir)
    return kg


def load_knowledge_graph(project_path: str) -> Optional[CodeKnowledgeGraph]:
    """加载已有的知识图谱（不存在则返回 None）"""
    kg = CodeKnowledgeGraph(project_path)
    if kg.exists():
        return kg
    return None