# -*- coding: utf-8 -*-
"""
Cache Manager —— 项目缓存和硬编码优化管理

管理 cache/ 目录下的所有用户专属数据：
1. config.json          —— LLM API 配置（从 config/ 迁移）
2. hardcoded/{hash}/    —— 项目专属硬编码优化（误报白名单 + 漏报补充规则）
3. llm_reviews/{hash}/  —— LLM 审查记录

设计原则：
- 开源时删除 cache/ 目录即可，代码库不包含任何敏感信息
- 每个项目独立缓存，通过 project_hash 隔离
- 支持 setup.bat 的 cache 管理命令（清理、重建、列表）
"""

import os
import json
import re
import hashlib
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple
from dataclasses import dataclass, field, asdict


# ─── 缓存根目录（相对于项目根目录） ───
_CACHE_ROOT = Path(__file__).parent.parent / "cache"


# ============================================================
# 数据模型
# ============================================================

@dataclass
class IntegrityWhitelistEntry:
    """完整性检查白名单条目 —— 跳过 todo_fixme、doc_coverage 等误报"""
    category: str
    file: str
    line: int = 0
    reason: str = ""
    reviewed_by: str = "manual"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class ResourceGapWhitelistEntry:
    """资源缺口白名单条目 —— 跳过 missing_module、dynamic_import 等误报"""
    category: str
    item: str
    file: str = ""
    reason: str = ""
    reviewed_by: str = "manual"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class BlindSpotWhitelistEntry:
    """盲区检测白名单条目 —— 跳过 doc_blindspot、missing_dependency 等误报"""
    category: str
    item: str
    file: str = ""
    reason: str = ""
    reviewed_by: str = "manual"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class AnalysisWhitelistEntry:
    """项目分析白名单条目 —— 跳过代码结构分析中的误报"""
    category: str
    file: str
    reason: str = ""
    reviewed_by: str = "manual"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class SimplifyWhitelistEntry:
    """简化建议白名单条目 —— 跳过 dead_code、large_function 等误报"""
    category: str
    function: str
    file: str = ""
    reason: str = ""
    reviewed_by: str = "manual"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class JunkWhitelistEntry:
    """垃圾文件白名单条目 —— 跳过 empty_shell、orphan 文件等误报"""
    category: str
    file: str
    reason: str = ""
    reviewed_by: str = "manual"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class SCAWhitelistEntry:
    """SCA扫描白名单条目 —— 跳过不影响生产的 CVE 误报"""
    package: str
    cve_id: str
    reason: str = ""
    reviewed_by: str = "manual"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class BusinessAnalysisWhitelistEntry:
    """业务分析白名单条目 —— 跳过第三方代码被误认为业务模块"""
    entity_type: str
    name: str
    reason: str = ""
    reviewed_by: str = "manual"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class InnovationGapWhitelistEntry:
    """创新缺口白名单条目 —— 跳过第三方代码与项目代码的差异"""
    module: str
    pattern: str
    reason: str = ""
    reviewed_by: str = "manual"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class MagicNumberEntry:
    """魔法数字白名单条目"""
    value: str
    file_pattern: str = "*.py"
    location: str = ""
    reason: str = ""
    reviewed_by: str = "manual"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class SecurityWhitelistEntry:
    """安全规则误报白名单条目"""
    rule_id: str
    file: str
    line: int = 0
    code_pattern: str = ""
    reason: str = ""
    reviewed_by: str = "manual"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class ComplexityExemptionEntry:
    """复杂度豁免条目"""
    function: str
    file: str
    reason: str = ""
    reviewed_by: str = "manual"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class NamingExemptionEntry:
    """命名豁免条目"""
    name: str
    file_pattern: str = "*.py"
    reason: str = ""
    reviewed_by: str = "manual"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class MagicNumberPatternEntry:
    """魔法数字模式白名单条目 —— 一条规则覆盖几百个条目"""
    value_pattern: str  # 正则表达式，匹配数字值
    file_pattern: str = "*.py"  # glob 模式，匹配文件名
    reason: str = ""
    reviewed_by: str = "ai"
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class LlmReviewRecord:
    """LLM 审查记录"""
    project_hash: str
    total_issues: int
    false_positives: int
    false_negatives: int
    suggestions: List[Dict] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


# ============================================================
# Cache Manager
# ============================================================

class CacheManager:
    """缓存管理器 —— 单例模式"""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self._cache_root = _CACHE_ROOT
        self._current_hash: Optional[str] = None
        self._magic_whitelist: Dict[str, Set[str]] = {}    # {value -> {file_patterns}}
        self._magic_pattern_whitelist: List[Tuple[re.Pattern, str, str]] = []  # [(compiled_regex, file_glob, reason)]
        self._security_whitelist: Dict[str, Set[Tuple]] = {} # {rule_id -> {(file, line)}}
        self._complexity_exemptions: Dict[str, Set[Tuple]] = {} # {function -> {(file,)}}
        self._naming_exemptions: Set[str] = set()
        self._integrity_whitelist: Dict[str, Set[Tuple]] = {}  # {category -> {(file, line)}}
        self._resource_gap_whitelist: Dict[str, Set[Tuple]] = {}  # {category -> {(item, file)}}
        self._blind_spot_whitelist: Dict[str, Set[Tuple]] = {}  # {category -> {(item, file)}}
        self._analysis_whitelist: Dict[str, Set[str]] = {}  # {category -> {file}}
        self._simplify_whitelist: Dict[str, Set[Tuple]] = {}  # {category -> {(function, file)}}
        self._junk_whitelist: Dict[str, Set[str]] = {}  # {category -> {file}}
        self._sca_whitelist: Dict[str, Set[str]] = {}  # {package -> {cve_id}}
        self._business_analysis_whitelist: Dict[str, Set[str]] = {}  # {entity_type -> {name}}
        self._innovation_gap_whitelist: Dict[str, Set[str]] = {}  # {module -> {pattern}}
        self._ensure_dirs()

    # ─── 目录管理 ───

    def _ensure_dirs(self):
        """确保缓存目录结构存在"""
        (self._cache_root / "hardcoded").mkdir(parents=True, exist_ok=True)
        (self._cache_root / "llm_reviews").mkdir(parents=True, exist_ok=True)

    @staticmethod
    def compute_project_hash(project_path: str) -> str:
        """计算项目路径的哈希值"""
        return hashlib.md5(os.path.abspath(project_path).encode('utf-8')).hexdigest()[:12]

    def get_hardcoded_dir(self, project_path: str) -> Path:
        """获取项目专属的硬编码缓存目录"""
        h = self.compute_project_hash(project_path)
        d = self._cache_root / "hardcoded" / h
        d.mkdir(parents=True, exist_ok=True)
        return d

    def get_llm_review_dir(self, project_path: str) -> Path:
        """获取项目专属的 LLM 审查目录"""
        h = self.compute_project_hash(project_path)
        d = self._cache_root / "llm_reviews" / h
        d.mkdir(parents=True, exist_ok=True)
        return d

    # ─── 配置管理 ───

    def get_config_path(self) -> Path:
        """获取缓存的配置文件路径"""
        return self._cache_root / "config.json"

    def load_config(self) -> Dict[str, Any]:
        """从 cache 加载配置，如果不存在则从 config/ 迁移"""
        cache_config = self.get_config_path()
        if cache_config.exists():
            with open(cache_config, "r", encoding="utf-8") as f:
                return json.load(f)

        # 迁移：从 config/config.json 复制到 cache/
        legacy_config = Path(__file__).parent.parent / "config" / "config.json"
        if legacy_config.exists():
            with open(legacy_config, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.save_config(data)
            return data

        return {}

    def save_config(self, data: Dict[str, Any]):
        """保存配置到 cache/"""
        self.get_config_path().parent.mkdir(parents=True, exist_ok=True)
        with open(self.get_config_path(), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    # ─── 硬编码优化：加载 ───

    def load_hardcoded(self, project_path: str):
        """
        加载项目专属的硬编码优化数据到内存。
        每次扫描前调用，确保使用最新的缓存。
        """
        d = self.get_hardcoded_dir(project_path)
        self._current_hash = self.compute_project_hash(project_path)

        # 加载魔法数字白名单
        magic_file = d / "magic_numbers.json"
        self._magic_whitelist.clear()
        if magic_file.exists():
            with open(magic_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for entry in data.get("entries", []):
                val = str(entry["value"])
                pat = entry.get("file_pattern", "*.py")
                if val not in self._magic_whitelist:
                    self._magic_whitelist[val] = set()
                self._magic_whitelist[val].add(pat)

        # 加载魔法数字模式白名单
        magic_pattern_file = d / "magic_number_patterns.json"
        self._magic_pattern_whitelist.clear()
        if magic_pattern_file.exists():
            with open(magic_pattern_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for entry in data.get("entries", []):
                try:
                    compiled = re.compile(entry["value_pattern"])
                    file_glob = entry.get("file_pattern", "*.py")
                    reason = entry.get("reason", "")
                    self._magic_pattern_whitelist.append((compiled, file_glob, reason))
                except re.error:
                    continue

        # 加载安全规则白名单
        sec_file = d / "security_whitelist.json"
        self._security_whitelist.clear()
        if sec_file.exists():
            with open(sec_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for entry in data.get("entries", []):
                rid = entry["rule_id"]
                key = (entry.get("file", ""), entry.get("line", 0))
                if rid not in self._security_whitelist:
                    self._security_whitelist[rid] = set()
                self._security_whitelist[rid].add(key)

        # 加载复杂度豁免
        cc_file = d / "complexity_exemptions.json"
        self._complexity_exemptions.clear()
        if cc_file.exists():
            with open(cc_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for entry in data.get("entries", []):
                func = entry["function"]
                key = (entry.get("file", ""),)
                if func not in self._complexity_exemptions:
                    self._complexity_exemptions[func] = set()
                self._complexity_exemptions[func].add(key)

        # 加载命名豁免
        naming_file = d / "naming_exemptions.json"
        self._naming_exemptions.clear()
        if naming_file.exists():
            with open(naming_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for entry in data.get("entries", []):
                self._naming_exemptions.add(entry["name"])

        # 加载完整性检查白名单
        integrity_file = d / "integrity_whitelist.json"
        self._integrity_whitelist.clear()
        if integrity_file.exists():
            with open(integrity_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for entry in data.get("entries", []):
                cat = entry["category"]
                key = (entry.get("file", ""), entry.get("line", 0))
                if cat not in self._integrity_whitelist:
                    self._integrity_whitelist[cat] = set()
                self._integrity_whitelist[cat].add(key)

        # 加载资源缺口白名单
        resource_gap_file = d / "resource_gap_whitelist.json"
        self._resource_gap_whitelist.clear()
        if resource_gap_file.exists():
            with open(resource_gap_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for entry in data.get("entries", []):
                cat = entry["category"]
                key = (entry.get("item", ""), entry.get("file", ""))
                if cat not in self._resource_gap_whitelist:
                    self._resource_gap_whitelist[cat] = set()
                self._resource_gap_whitelist[cat].add(key)

        # 加载盲区检测白名单
        blind_spot_file = d / "blind_spot_whitelist.json"
        self._blind_spot_whitelist.clear()
        if blind_spot_file.exists():
            with open(blind_spot_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for entry in data.get("entries", []):
                cat = entry["category"]
                key = (entry.get("item", ""), entry.get("file", ""))
                if cat not in self._blind_spot_whitelist:
                    self._blind_spot_whitelist[cat] = set()
                self._blind_spot_whitelist[cat].add(key)

        # 加载项目分析白名单
        analysis_file = d / "analysis_whitelist.json"
        self._analysis_whitelist.clear()
        if analysis_file.exists():
            with open(analysis_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for entry in data.get("entries", []):
                cat = entry["category"]
                fname = entry.get("file", "")
                if cat not in self._analysis_whitelist:
                    self._analysis_whitelist[cat] = set()
                self._analysis_whitelist[cat].add(fname)

        # 加载简化建议白名单
        simplify_file = d / "simplify_whitelist.json"
        self._simplify_whitelist.clear()
        if simplify_file.exists():
            with open(simplify_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for entry in data.get("entries", []):
                cat = entry["category"]
                key = (entry.get("function", ""), entry.get("file", ""))
                if cat not in self._simplify_whitelist:
                    self._simplify_whitelist[cat] = set()
                self._simplify_whitelist[cat].add(key)

        # 加载垃圾文件白名单
        junk_file = d / "junk_whitelist.json"
        self._junk_whitelist.clear()
        if junk_file.exists():
            with open(junk_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for entry in data.get("entries", []):
                cat = entry["category"]
                fname = entry.get("file", "")
                if cat not in self._junk_whitelist:
                    self._junk_whitelist[cat] = set()
                self._junk_whitelist[cat].add(fname)

        # 加载SCA扫描白名单
        sca_file = d / "sca_whitelist.json"
        self._sca_whitelist.clear()
        if sca_file.exists():
            with open(sca_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for entry in data.get("entries", []):
                pkg = entry["package"]
                cve = entry.get("cve_id", "")
                if pkg not in self._sca_whitelist:
                    self._sca_whitelist[pkg] = set()
                self._sca_whitelist[pkg].add(cve)

        # 加载业务分析白名单
        business_analysis_file = d / "business_analysis_whitelist.json"
        self._business_analysis_whitelist.clear()
        if business_analysis_file.exists():
            with open(business_analysis_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for entry in data.get("entries", []):
                etype = entry["entity_type"]
                name = entry.get("name", "")
                if etype not in self._business_analysis_whitelist:
                    self._business_analysis_whitelist[etype] = set()
                self._business_analysis_whitelist[etype].add(name)

        # 加载创新缺口白名单
        innovation_gap_file = d / "innovation_gap_whitelist.json"
        self._innovation_gap_whitelist.clear()
        if innovation_gap_file.exists():
            with open(innovation_gap_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            for entry in data.get("entries", []):
                mod = entry["module"]
                pat = entry.get("pattern", "")
                if mod not in self._innovation_gap_whitelist:
                    self._innovation_gap_whitelist[mod] = set()
                self._innovation_gap_whitelist[mod].add(pat)

    # ─── 硬编码优化：查询 ───

    def is_magic_whitelisted(self, value: str, file_path: str = "") -> bool:
        """检查魔法数字是否在白名单中（精确匹配 + 模式匹配）"""
        val = str(value)
        fname = os.path.basename(file_path)

        # 精确匹配
        if val in self._magic_whitelist:
            patterns = self._magic_whitelist[val]
            if "*.py" in patterns:
                return True
            for pat in patterns:
                if pat == fname:
                    return True

        # 模式匹配（一条规则覆盖几百个条目）
        import fnmatch
        for compiled_re, file_glob, reason in self._magic_pattern_whitelist:
            if compiled_re.search(val):
                if file_glob == "*.py" or fnmatch.fnmatch(fname, file_glob):
                    return True

        return False

    def is_security_whitelisted(self, rule_id: str, file_path: str = "", line: int = 0) -> bool:
        """检查安全规则是否在白名单中"""
        if rule_id in self._security_whitelist:
            entries = self._security_whitelist[rule_id]
            fname = os.path.basename(file_path) if file_path else ""
            # 精确匹配（文件+行号）
            if (fname, line) in entries:
                return True
            # 通配匹配（文件=* 或 line=0 表示忽略该项）
            if ("*", 0) in entries or (fname, 0) in entries:
                return True
        return False

    def is_complexity_exempted(self, function_name: str, file_path: str = "") -> bool:
        """检查函数是否在复杂度豁免列表中"""
        if function_name in self._complexity_exemptions:
            entries = self._complexity_exemptions[function_name]
            fname = os.path.basename(file_path) if file_path else ""
            if ("*",) in entries or (fname,) in entries:
                return True
        return False

    def is_naming_exempted(self, name: str) -> bool:
        """检查命名是否在豁免列表中"""
        return name in self._naming_exemptions

    def is_integrity_whitelisted(self, category: str, file_path: str = "", line: int = 0) -> bool:
        """检查完整性检查条目是否在白名单中"""
        if category in self._integrity_whitelist:
            entries = self._integrity_whitelist[category]
            fname = os.path.basename(file_path) if file_path else ""
            if (fname, line) in entries:
                return True
            if ("*", 0) in entries or (fname, 0) in entries:
                return True
        return False

    def is_resource_gap_whitelisted(self, category: str, item: str, file_path: str = "") -> bool:
        """检查资源缺口条目是否在白名单中"""
        if category in self._resource_gap_whitelist:
            entries = self._resource_gap_whitelist[category]
            fname = os.path.basename(file_path) if file_path else ""
            if (item, fname) in entries:
                return True
            if (item, "*") in entries or ("*", fname) in entries or ("*", "*") in entries:
                return True
        return False

    def is_blind_spot_whitelisted(self, category: str, item: str, file_path: str = "") -> bool:
        """检查盲区检测条目是否在白名单中"""
        if category in self._blind_spot_whitelist:
            entries = self._blind_spot_whitelist[category]
            fname = os.path.basename(file_path) if file_path else ""
            if (item, fname) in entries:
                return True
            if (item, "*") in entries or ("*", fname) in entries or ("*", "*") in entries:
                return True
        return False

    def is_analysis_whitelisted(self, category: str, file_path: str = "") -> bool:
        """检查项目分析条目是否在白名单中"""
        if category in self._analysis_whitelist:
            entries = self._analysis_whitelist[category]
            fname = os.path.basename(file_path) if file_path else ""
            if fname in entries or "*" in entries:
                return True
        return False

    def is_simplify_whitelisted(self, category: str, function_name: str, file_path: str = "") -> bool:
        """检查简化建议条目是否在白名单中"""
        if category in self._simplify_whitelist:
            entries = self._simplify_whitelist[category]
            fname = os.path.basename(file_path) if file_path else ""
            if (function_name, fname) in entries:
                return True
            if (function_name, "*") in entries or ("*", fname) in entries:
                return True
        return False

    def is_junk_whitelisted(self, category: str, file_path: str = "") -> bool:
        """检查垃圾文件条目是否在白名单中"""
        if category in self._junk_whitelist:
            entries = self._junk_whitelist[category]
            fname = os.path.basename(file_path) if file_path else ""
            if fname in entries or "*" in entries:
                return True
        return False

    def is_sca_whitelisted(self, package: str, cve_id: str = "") -> bool:
        """检查SCA扫描条目是否在白名单中"""
        if package in self._sca_whitelist:
            entries = self._sca_whitelist[package]
            if cve_id in entries or "*" in entries:
                return True
        return False

    def is_business_analysis_whitelisted(self, entity_type: str, name: str = "") -> bool:
        """检查业务分析条目是否在白名单中"""
        if entity_type in self._business_analysis_whitelist:
            entries = self._business_analysis_whitelist[entity_type]
            if name in entries or "*" in entries:
                return True
        return False

    def is_innovation_gap_whitelisted(self, module: str, pattern: str = "") -> bool:
        """检查创新缺口条目是否在白名单中"""
        if module in self._innovation_gap_whitelist:
            entries = self._innovation_gap_whitelist[module]
            if pattern in entries or "*" in entries:
                return True
        return False

    # ─── 硬编码优化：保存（LLM 审查后调用） ───

    def save_magic_whitelist(self, project_path: str, entries: List[MagicNumberEntry]):
        """保存魔法数字白名单"""
        d = self.get_hardcoded_dir(project_path)
        data = {"entries": [asdict(e) for e in entries], "updated": datetime.now().isoformat()}
        with open(d / "magic_numbers.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def save_magic_pattern_whitelist(self, project_path: str, entries: List[MagicNumberPatternEntry]):
        """保存魔法数字模式白名单（一条规则覆盖几百个条目）"""
        d = self.get_hardcoded_dir(project_path)
        data = {"entries": [asdict(e) for e in entries], "updated": datetime.now().isoformat()}
        with open(d / "magic_number_patterns.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def save_security_whitelist(self, project_path: str, entries: List[SecurityWhitelistEntry]):
        """保存安全规则白名单"""
        d = self.get_hardcoded_dir(project_path)
        data = {"entries": [asdict(e) for e in entries], "updated": datetime.now().isoformat()}
        with open(d / "security_whitelist.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def save_complexity_exemptions(self, project_path: str, entries: List[ComplexityExemptionEntry]):
        """保存复杂度豁免"""
        d = self.get_hardcoded_dir(project_path)
        data = {"entries": [asdict(e) for e in entries], "updated": datetime.now().isoformat()}
        with open(d / "complexity_exemptions.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def save_naming_exemptions(self, project_path: str, entries: List[NamingExemptionEntry]):
        """保存命名豁免"""
        d = self.get_hardcoded_dir(project_path)
        data = {"entries": [asdict(e) for e in entries], "updated": datetime.now().isoformat()}
        with open(d / "naming_exemptions.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def save_integrity_whitelist(self, project_path: str, entries: List[IntegrityWhitelistEntry]):
        """保存完整性检查白名单"""
        d = self.get_hardcoded_dir(project_path)
        data = {"entries": [asdict(e) for e in entries], "updated": datetime.now().isoformat()}
        with open(d / "integrity_whitelist.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def save_resource_gap_whitelist(self, project_path: str, entries: List[ResourceGapWhitelistEntry]):
        """保存资源缺口白名单"""
        d = self.get_hardcoded_dir(project_path)
        data = {"entries": [asdict(e) for e in entries], "updated": datetime.now().isoformat()}
        with open(d / "resource_gap_whitelist.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def save_blind_spot_whitelist(self, project_path: str, entries: List[BlindSpotWhitelistEntry]):
        """保存盲区检测白名单"""
        d = self.get_hardcoded_dir(project_path)
        data = {"entries": [asdict(e) for e in entries], "updated": datetime.now().isoformat()}
        with open(d / "blind_spot_whitelist.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def save_analysis_whitelist(self, project_path: str, entries: List[AnalysisWhitelistEntry]):
        """保存项目分析白名单"""
        d = self.get_hardcoded_dir(project_path)
        data = {"entries": [asdict(e) for e in entries], "updated": datetime.now().isoformat()}
        with open(d / "analysis_whitelist.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def save_simplify_whitelist(self, project_path: str, entries: List[SimplifyWhitelistEntry]):
        """保存简化建议白名单"""
        d = self.get_hardcoded_dir(project_path)
        data = {"entries": [asdict(e) for e in entries], "updated": datetime.now().isoformat()}
        with open(d / "simplify_whitelist.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def save_junk_whitelist(self, project_path: str, entries: List[JunkWhitelistEntry]):
        """保存垃圾文件白名单"""
        d = self.get_hardcoded_dir(project_path)
        data = {"entries": [asdict(e) for e in entries], "updated": datetime.now().isoformat()}
        with open(d / "junk_whitelist.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def save_sca_whitelist(self, project_path: str, entries: List[SCAWhitelistEntry]):
        """保存SCA扫描白名单"""
        d = self.get_hardcoded_dir(project_path)
        data = {"entries": [asdict(e) for e in entries], "updated": datetime.now().isoformat()}
        with open(d / "sca_whitelist.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def save_business_analysis_whitelist(self, project_path: str, entries: List[BusinessAnalysisWhitelistEntry]):
        """保存业务分析白名单"""
        d = self.get_hardcoded_dir(project_path)
        data = {"entries": [asdict(e) for e in entries], "updated": datetime.now().isoformat()}
        with open(d / "business_analysis_whitelist.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def save_innovation_gap_whitelist(self, project_path: str, entries: List[InnovationGapWhitelistEntry]):
        """保存创新缺口白名单"""
        d = self.get_hardcoded_dir(project_path)
        data = {"entries": [asdict(e) for e in entries], "updated": datetime.now().isoformat()}
        with open(d / "innovation_gap_whitelist.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    # ─── LLM 审查记录 ───

    def save_llm_review(self, project_path: str, review: LlmReviewRecord):
        """保存 LLM 审查结果"""
        d = self.get_llm_review_dir(project_path)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        with open(d / f"review_{ts}.json", "w", encoding="utf-8") as f:
            json.dump(asdict(review), f, indent=2, ensure_ascii=False)

    def list_llm_reviews(self, project_path: str) -> List[Path]:
        """列出项目的所有 LLM 审查记录"""
        d = self.get_llm_review_dir(project_path)
        return sorted(d.glob("review_*.json"))

    # ─── Cache 管理 ───

    def list_projects(self) -> List[Dict[str, str]]:
        """列出所有有缓存的项目"""
        result = []
        hardcoded_dir = self._cache_root / "hardcoded"
        if hardcoded_dir.exists():
            for h in hardcoded_dir.iterdir():
                if h.is_dir():
                    # 尝试读取项目信息
                    info_file = h / "project_info.json"
                    info = {"hash": h.name, "path": "未知"}
                    if info_file.exists():
                        with open(info_file, "r", encoding="utf-8") as f:
                            info.update(json.load(f))
                    # 统计条目数
                    files = list(h.glob("*.json"))
                    sizes = sum(f.stat().st_size for f in files if f.name != "project_info.json")
                    info["files"] = len(files) - (1 if info_file.exists() else 0)
                    info["size_kb"] = round(sizes / 1024, 1)
                    result.append(info)
        return result

    def clear_project_cache(self, project_path: str):
        """清除指定项目的缓存"""
        h = self.compute_project_hash(project_path)
        d = self._cache_root / "hardcoded" / h
        if d.exists():
            shutil.rmtree(d)
        d = self._cache_root / "llm_reviews" / h
        if d.exists():
            shutil.rmtree(d)

    def clear_all_cache(self):
        """清除所有缓存（保留 config.json）"""
        config_path = self.get_config_path()
        config_data = None
        if config_path.exists():
            with open(config_path, "r", encoding="utf-8") as f:
                config_data = f.read()

        if self._cache_root.exists():
            shutil.rmtree(self._cache_root)
        self._ensure_dirs()

        if config_data:
            with open(config_path, "w", encoding="utf-8") as f:
                f.write(config_data)

    def export_snapshot(self, project_path: str) -> Dict[str, Any]:
        """导出当前项目的缓存快照（用于 LLM 审查）"""
        h = self.compute_project_hash(project_path)
        d = self.get_hardcoded_dir(project_path)
        snapshot = {
            "project_hash": h,
            "project_path": project_path,
            "exported_at": datetime.now().isoformat(),
            "magic_numbers": [],
            "security_whitelist": [],
            "complexity_exemptions": [],
            "naming_exemptions": [],
            "integrity_whitelist": [],
            "resource_gap_whitelist": [],
            "blind_spot_whitelist": [],
            "analysis_whitelist": [],
            "simplify_whitelist": [],
            "junk_whitelist": [],
            "sca_whitelist": [],
            "business_analysis_whitelist": [],
            "innovation_gap_whitelist": [],
        }
        for fname, key in [
            ("magic_numbers.json", "magic_numbers"),
            ("security_whitelist.json", "security_whitelist"),
            ("complexity_exemptions.json", "complexity_exemptions"),
            ("naming_exemptions.json", "naming_exemptions"),
            ("integrity_whitelist.json", "integrity_whitelist"),
            ("resource_gap_whitelist.json", "resource_gap_whitelist"),
            ("blind_spot_whitelist.json", "blind_spot_whitelist"),
            ("analysis_whitelist.json", "analysis_whitelist"),
            ("simplify_whitelist.json", "simplify_whitelist"),
            ("junk_whitelist.json", "junk_whitelist"),
            ("sca_whitelist.json", "sca_whitelist"),
            ("business_analysis_whitelist.json", "business_analysis_whitelist"),
            ("innovation_gap_whitelist.json", "innovation_gap_whitelist"),
        ]:
            f = d / fname
            if f.exists():
                with open(f, "r", encoding="utf-8") as fp:
                    snapshot[key] = json.load(fp).get("entries", [])
        return snapshot


# 全局单例
cache_manager = CacheManager()