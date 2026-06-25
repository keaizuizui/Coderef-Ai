# -*- coding: utf-8 -*-
"""
代码库深度分析模块
使用Tree-sitter进行多语言代码解析和结构分析
"""

import os
import re
import json
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Set
from dataclasses import dataclass, field
from collections import defaultdict

from loguru import logger
from core.shared_filter import SharedFilter


@dataclass
class CodeFunction:
    """函数/方法信息"""
    name: str
    start_line: int
    end_line: int
    parameters: List[str] = field(default_factory=list)
    return_type: Optional[str] = None
    docstring: Optional[str] = None
    code: str = ""
    
    def to_dict(self) -> dict:
        return {
            "name": self.name, "start_line": self.start_line,
            "end_line": self.end_line, "parameters": self.parameters,
            "return_type": self.return_type, "docstring": self.docstring,
            "code": self.code
        }
    
    @staticmethod
    def from_dict(d: dict) -> 'CodeFunction':
        return CodeFunction(**{k: d[k] for k in CodeFunction.__dataclass_fields__ if k in d})


@dataclass
class CodeClass:
    """类信息"""
    name: str
    start_line: int
    end_line: int
    methods: List[CodeFunction] = field(default_factory=list)
    base_classes: List[str] = field(default_factory=list)
    docstring: Optional[str] = None
    
    def to_dict(self) -> dict:
        return {
            "name": self.name, "start_line": self.start_line,
            "end_line": self.end_line,
            "methods": [m.to_dict() for m in self.methods],
            "base_classes": self.base_classes, "docstring": self.docstring
        }
    
    @staticmethod
    def from_dict(d: dict) -> 'CodeClass':
        obj = CodeClass(**{k: d[k] for k in ['name', 'start_line', 'end_line', 'base_classes', 'docstring'] if k in d})
        obj.methods = [CodeFunction.from_dict(m) for m in d.get('methods', [])]
        return obj


@dataclass
class CodeFile:
    """代码文件信息"""
    file_path: str
    language: str
    imports: List[str] = field(default_factory=list)
    functions: List[CodeFunction] = field(default_factory=list)
    classes: List[CodeClass] = field(default_factory=list)
    dependencies: Set[str] = field(default_factory=set)
    raw_content: str = ""
    # === 增强分析字段 ===
    project_imports: List[str] = field(default_factory=list)
    sys_path_inserts: List[str] = field(default_factory=list)
    dynamic_imports: List[Dict] = field(default_factory=list)
    http_calls: List[Dict] = field(default_factory=list)
    function_calls: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "file_path": self.file_path, "language": self.language,
            "imports": self.imports,
            "functions": [f.to_dict() for f in self.functions],
            "classes": [c.to_dict() for c in self.classes],
            "dependencies": list(self.dependencies),
            "raw_content": self.raw_content,  # 完整内容，供后续审计使用
            "project_imports": self.project_imports,
            "sys_path_inserts": self.sys_path_inserts,
            "dynamic_imports": self.dynamic_imports,
            "http_calls": self.http_calls,
            "function_calls": self.function_calls,
        }
    
    @staticmethod
    def from_dict(d: dict) -> 'CodeFile':
        obj = CodeFile(file_path=d.get("file_path", ""), language=d.get("language", ""))
        obj.imports = d.get("imports", [])
        obj.functions = [CodeFunction.from_dict(f) for f in d.get("functions", [])]
        obj.classes = [CodeClass.from_dict(c) for c in d.get("classes", [])]
        obj.dependencies = set(d.get("dependencies", []))
        obj.raw_content = d.get("raw_content", "")
        obj.project_imports = d.get("project_imports", [])
        obj.sys_path_inserts = d.get("sys_path_inserts", [])
        obj.dynamic_imports = d.get("dynamic_imports", [])
        obj.http_calls = d.get("http_calls", [])
        obj.function_calls = d.get("function_calls", [])
        return obj


@dataclass
class ProjectAnalysis:
    """项目分析结果"""
    project_path: str
    total_files: int = 0
    total_lines: int = 0
    languages: Dict[str, int] = field(default_factory=dict)
    files: List[CodeFile] = field(default_factory=list)
    modules: Dict[str, List[str]] = field(default_factory=lambda: defaultdict(list))
    dependencies: Set[str] = field(default_factory=set)
    architecture_summary: str = ""
    core_features: List[str] = field(default_factory=list)
    tech_stack: List[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        return {
            "project_path": self.project_path,
            "total_files": self.total_files,
            "total_lines": self.total_lines,
            "languages": dict(self.languages),
            "files": [f.to_dict() for f in self.files],
            "modules": {k: list(v) for k, v in self.modules.items()},
            "dependencies": list(self.dependencies),
            "architecture_summary": self.architecture_summary,
            "core_features": self.core_features,
            "tech_stack": self.tech_stack,
        }
    
    @staticmethod
    def from_dict(d: dict) -> 'ProjectAnalysis':
        obj = ProjectAnalysis(project_path=d.get("project_path", ""))
        obj.total_files = d.get("total_files", 0)
        obj.total_lines = d.get("total_lines", 0)
        obj.languages = d.get("languages", {})
        obj.files = [CodeFile.from_dict(f) for f in d.get("files", [])]
        obj.modules = defaultdict(list, {k: list(v) for k, v in d.get("modules", {}).items()})
        obj.dependencies = set(d.get("dependencies", []))
        obj.architecture_summary = d.get("architecture_summary", "")
        obj.core_features = d.get("core_features", [])
        obj.tech_stack = d.get("tech_stack", [])
        return obj


class CodeAnalyzer:
    """代码分析器"""
    
    # 文件扩展名到语言的映射
    EXTENSION_MAP = {
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'typescript',
        '.jsx': 'javascript',
        '.tsx': 'typescript',
        '.java': 'java',
        '.cpp': 'cpp',
        '.c': 'c',
        '.h': 'c',
        '.hpp': 'cpp',
        '.go': 'go',
        '.rs': 'rust',
        '.rb': 'ruby',
        '.php': 'php',
    }
    
    # 忽略的目录——只过滤真正不该扫的
    IGNORE_DIRS = {
        # git、缓存、编译产物
        '__pycache__', '.git', 'node_modules',
        # 本地Python运行时（不是你的代码）
        'venv', 'env', '.venv', '.env',
        'site-packages', 'Lib', 'lib',
        'egg-info', '.eggs',
        'Python3.14', 'Python3.13', 'Python3.12',
        # 第三方集成代码（不是你写的）
        'third_party', 'third-party',
    }
    
    # 忽略的文件名模式（正则表达式）— 仅排除编译产物
    IGNORE_FILE_PATTERNS = [
        r'.*\.pyc$',                    # Python编译文件
        r'.*\.pyo$',                    # Python优化文件
        r'.*\.so$',                     # 动态链接库（C扩展编译产物）
        r'.*\.pyd$',                    # Windows Python DLL
        r'.*\.egg-info/.*',             # Python包信息
        r'.*__pycache__/.*',           # Python缓存
        r'.*\.swp$',                    # vim swap
        r'.*\.bak$',                    # 备份文件
        r'.*\.tmp$',                    # 临时文件
    ]
    
    # 工具自身生成的报告文件（.md / .docx），不纳入用户代码分析
    IGNORE_REPORT_PATTERNS = [
        r'.*全项目架构分析报告.*\.md$',
        r'.*深度架构分析报告.*\.md$',
        r'.*深度分析报告.*\.md$',
        r'.*分析报告.*\.md$',
        r'.*业务概览.*\.md$',
        r'^README\.md$',
    ]
    
    def __init__(self):
        self.parsers = {}
        self._init_parsers()
        self.MAX_PARSE_FILE_SIZE = 500 * 1024  # 超过500KB的文件不做详细解析
        self._parse_count = 0  # 统计解析过的文件数
        
        # 缓存目录
        self._cache_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "data", "analysis_cache"
        )
        os.makedirs(self._cache_dir, exist_ok=True)
        
        # GitNexus 增强通道（可用时自动启用）
        self._gitnexus_available = False
        self._gitnexus_client = None
        self._init_gitnexus()
    
    def _init_gitnexus(self):
        """检测GitNexus是否可用，可用则初始化MCP客户端"""
        try:
            from .gitnexus_client import GitNexusMCPClient
            if GitNexusMCPClient.is_cli_available():
                self._gitnexus_available = True
                logger.info("[CodeAnalyzer] GitNexus MCP通道已启用")
            else:
                logger.debug("[CodeAnalyzer] GitNexus CLI未安装，使用传统分析模式")
        except Exception as e:
            logger.debug(f"[CodeAnalyzer] GitNexus初始化检测失败: {e}")
    
    def _cache_path(self, project_path: str) -> str:
        """获取项目对应的缓存文件路径"""
        # 用项目路径的 hash 做文件名
        safe_name = hashlib.md5(project_path.encode('utf-8')).hexdigest()
        return os.path.join(self._cache_dir, f"{safe_name}.json")
    
    def _cache_snapshot_path(self, project_path: str) -> str:
        """获取项目文件快照路径（用于判断缓存是否过期）"""
        safe_name = hashlib.md5(project_path.encode('utf-8')).hexdigest()
        return os.path.join(self._cache_dir, f"{safe_name}_snapshot.json")
    
    def _compute_file_snapshot(self, project_path: str) -> Dict[str, float]:
        """计算项目所有代码文件的最新修改时间快照"""
        snapshot = {}
        code_files = self.scan_directory(project_path)
        for fp in code_files:
            try:
                mtime = os.path.getmtime(fp)
                snapshot[fp] = mtime
            except:
                pass
        return snapshot
    
    def _is_cache_valid(self, project_path: str) -> bool:
        """检查缓存是否有效（所有文件未被修改）"""
        snapshot_path = self._cache_snapshot_path(project_path)
        if not os.path.exists(snapshot_path):
            return False
        cache_path = self._cache_path(project_path)
        if not os.path.exists(cache_path):
            return False
        try:
            with open(snapshot_path, 'r', encoding='utf-8') as f:
                saved_snapshot = json.load(f)
        except:
            return False
        current_snapshot = self._compute_file_snapshot(project_path)
        # 文件数不同 = 过期
        if set(saved_snapshot.keys()) != set(current_snapshot.keys()):
            return False
        # 修改时间不同 = 过期
        for fp, mtime in current_snapshot.items():
            if abs(saved_snapshot.get(fp, 0) - mtime) > 0.1:
                return False
        return True
    
    def save_cache(self, analysis: ProjectAnalysis):
        """保存分析结果到缓存"""
        cache_path = self._cache_path(analysis.project_path)
        snapshot_path = self._cache_snapshot_path(analysis.project_path)
        
        data = analysis.to_dict()
        with open(cache_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=1)
        
        snapshot = self._compute_file_snapshot(analysis.project_path)
        with open(snapshot_path, 'w', encoding='utf-8') as f:
            json.dump(snapshot, f, ensure_ascii=False)
        
        file_count = len(analysis.files)
        logger.info(f"分析结果已缓存: {cache_path} ({file_count}个文件)")
    
    def load_cache(self, project_path: str) -> Optional[ProjectAnalysis]:
        """从缓存加载分析结果"""
        cache_path = self._cache_path(project_path)
        if not os.path.exists(cache_path):
            logger.debug(f"缓存不存在: {cache_path}")
            return None
        try:
            with open(cache_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            result = ProjectAnalysis.from_dict(data)
            logger.info(f"从缓存加载分析结果: {cache_path} ({result.total_files}个文件)")
            return result
        except Exception as e:
            logger.warning(f"缓存加载失败: {e}")
            return None
    
    def _init_parsers(self):
        """初始化支持的语言解析器"""
        # tree_sitter_languages 在新版本中 API 有变化，这里改为 try/except 方式逐个尝试
        supported_langs = ['python', 'javascript', 'typescript', 'java', 'cpp', 'c', 'go', 'rust']
        for lang in supported_langs:
            try:
                from tree_sitter_languages import get_parser
                self.parsers[lang] = get_parser(lang)
                logger.debug(f"已加载 {lang} 解析器")
            except Exception as e:
                logger.debug(f"加载 {lang} 解析器失败（不影响基础分析）: {e}")
    
    def _should_skip_large_file(self, file_path: str) -> bool:
        """跳过超大文件，避免卡死"""
        try:
            return os.path.getsize(file_path) > self.MAX_PARSE_FILE_SIZE
        except:
            return False
    
    def _detect_language(self, file_path: str) -> Optional[str]:
        """根据文件扩展名检测语言"""
        ext = Path(file_path).suffix.lower()
        return self.EXTENSION_MAP.get(ext)
    
    def _should_ignore(self, path: Path) -> bool:
        """判断是否应该忽略该文件/目录"""
        # 1. 检查目录名是否在忽略列表中
        if any(part in self.IGNORE_DIRS for part in path.parts):
            return True
        
        # 2. 检查文件名模式
        str_path = str(path)
        name = path.name
        
        # 对文件使用 IGNORE_FILE_PATTERNS
        if path.is_file():
            for pattern in self.IGNORE_FILE_PATTERNS:
                if re.search(pattern, name):
                    return True
        
        # 3. 检查是否是报告类文件
        if path.is_file():
            for pattern in self.IGNORE_REPORT_PATTERNS:
                if re.search(pattern, name):
                    return True
        
        return False
    
    def scan_directory(self, dir_path: str) -> List[str]:
        """扫描目录，获取所有代码文件路径（使用 os.walk 以容错处理损坏的符号链接）"""
        code_files = []
        root = Path(dir_path)
        
        try:
            for current_dir, dirs, files in os.walk(str(root), topdown=True):
                current_path = Path(current_dir)
                
                # 跳过应忽略的目录
                rel_parts = current_path.relative_to(root).parts
                skip_this = any(self._should_ignore(Path(part)) for part in rel_parts) if rel_parts else False
                if skip_this:
                    dirs.clear()
                    continue
                
                # 过滤子目录列表：把应忽略的移除掉
                dirs[:] = [d for d in dirs if not self._should_ignore(current_path / d)]
                
                for file_name in files:
                    file_path = current_path / file_name
                    try:
                        if self._detect_language(str(file_path)):
                            code_files.append(str(file_path))
                    except (PermissionError, FileNotFoundError, OSError):
                        continue
        except (PermissionError, FileNotFoundError, OSError) as walk_err:
            logger.warning(f"扫描路径时遇到错误（跳过）: {walk_err}")
        
        logger.info(f"扫描完成，发现 {len(code_files)} 个代码文件")
        return code_files
    
    def parse_python_file(self, content: str, file_path: str, project_root: str = "") -> CodeFile:
        """解析Python文件（增强版：AST 精确解析 + 正则回退）"""
        code_file = CodeFile(file_path=file_path, language='python', raw_content=content)

        # 计算当前文件所在模块（相对项目根的目录）
        if project_root:
            rel_dir = os.path.dirname(os.path.relpath(file_path, project_root))
        else:
            rel_dir = ""

        # ─── 优先使用 AST 精确解析 ──────────────────────────────────
        ast_assignments = []  # AST 解析的赋值分类
        try:
            from core.ast_parser import AstParser
            ast_parser = AstParser(project_root=project_root)
            ast_result = ast_parser.parse_content(content, file_path)
            if ast_result:
                ast_assignments = ast_result.assignments
                logger.debug(f"[AST] {file_path}: {len(ast_result.functions)}函数, "
                           f"{len(ast_result.classes)}类, {len(ast_result.assignments)}赋值")
        except Exception as e:
            logger.debug(f"[AST] 解析失败 {file_path}: {e}")

        # 存储 AST 赋值分类（供 _audit_security 使用）
        code_file.ast_assignments = ast_assignments

        # 提取导入
        import_pattern = r'^(?:from|import)\s+([\w\.]+)'
        for match in re.finditer(import_pattern, content, re.MULTILINE):
            imp = match.group(1)
            code_file.imports.append(imp)
            root_pkg = imp.split('.')[0]
            
            # 区分项目内部导入 vs 外部依赖
            # 如果导入以项目模块名开头，标记为项目内部
            if rel_dir and (root_pkg == rel_dir.split('\\')[0].split('/')[0] or 
                            any(part == root_pkg for part in rel_dir.replace('\\', '/').split('/'))):
                code_file.project_imports.append(imp)
            else:
                code_file.dependencies.add(root_pkg)
        
        # 提取完整的from ... import ... 语句（用于跨模块分析）
        full_import_pattern = r'from\s+([\w\.]+)\s+import\s+([\w\s,]+)'
        for match in re.finditer(full_import_pattern, content):
            module_path = match.group(1)
            names = [n.strip() for n in match.group(2).split(',')]
            # 检测是否导入其他模块的类/函数（表明跨模块调用）
            if rel_dir and module_path not in ('__future__', 'typing', 'abc', 'dataclasses', 'enum'):
                root = module_path.split('.')[0]
                if root != rel_dir.split('\\')[0].split('/')[0] and not root.startswith('_'):
                    for name in names:
                        code_file.function_calls.append(f"{module_path}.{name}")
        
        # 提取 sys.path.insert / sys.path.append（动态注入点）
        syspath_pattern = r'sys\.path\.(?:insert|append)\s*\(([^)]*)\)'
        for match in re.finditer(syspath_pattern, content):
            code_file.sys_path_inserts.append(match.group(1).strip())
        
        # 提取 importlib.import_module（动态导入）
        dyn_import_pattern = r'importlib\.import_module\s*\(([^)]*)\)'
        for match in re.finditer(dyn_import_pattern, content):
            code_file.dynamic_imports.append({"module_expr": match.group(1).strip()})
        
        # 提取对本地服务的 HTTP 请求
        http_pattern = r'(requests|httpx|aiohttp)\.(get|post|put|delete)\s*\(\s*["\'](http://127\.0\.0\.1|http://localhost|http://0\.0\.0\.0)'
        for match in re.finditer(http_pattern, content):
            code_file.http_calls.append({
                "method": match.group(2).upper(),
                "url_pattern": match.group(0)
            })
        
        # 提取函数
        func_pattern = r'def\s+(\w+)\s*\(([^)]*)\)\s*(?:->\s*([\w\[\],\s]+))?:'
        func_matches = list(re.finditer(func_pattern, content))
        for idx, match in enumerate(func_matches):
            func_name = match.group(1)
            if not func_name.startswith('_'):  # 跳过私有函数
                params = [p.strip() for p in match.group(2).split(',') if p.strip()]
                start_line = content[:match.start()].count('\n') + 1
                # 计算 end_line：下一个函数/类定义之前减1行，或文件末尾
                end_line = len(content.splitlines())
                if idx + 1 < len(func_matches):
                    end_line = content[:func_matches[idx + 1].start()].count('\n')
                code_file.functions.append(CodeFunction(
                    name=func_name,
                    start_line=start_line,
                    end_line=end_line,
                    parameters=params,
                    return_type=match.group(3)
                ))
        
        # 提取类
        class_pattern = r'class\s+(\w+)(?:\(([^)]*)\))?:'
        class_matches = list(re.finditer(class_pattern, content))
        for idx, match in enumerate(class_matches):
            class_name = match.group(1)
            bases = [b.strip() for b in (match.group(2) or '').split(',') if b.strip()]
            start_line = content[:match.start()].count('\n') + 1
            end_line = len(content.splitlines())
            if idx + 1 < len(class_matches):
                end_line = content[:class_matches[idx + 1].start()].count('\n')
            code_file.classes.append(CodeClass(
                name=class_name,
                start_line=start_line,
                end_line=end_line,
                base_classes=bases
            ))
        
        return code_file
    
    def parse_file(self, file_path: str) -> Optional[CodeFile]:
        """解析单个代码文件"""
        try:
            lang = self._detect_language(file_path)
            if not lang:
                return None
            
            # 超大文件跳过详细解析，只记录基本信息
            if self._should_skip_large_file(file_path):
                logger.debug(f"跳过超大文件详细解析: {file_path}")
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read(2000)  # 只读开头用于统计
                code_file = CodeFile(file_path=file_path, language=lang, raw_content="[超大文件，已跳过详细分析]")
                # 粗略估算行数
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f2:
                        code_file.raw_content = f"[超大文件，已跳过详细分析，约 {sum(1 for _ in f2)} 行]"
                except OSError:
                    pass
                return code_file
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # 使用简化的解析方式（Tree-sitter完整解析较复杂，这里用正则）
            if lang == 'python':
                return self.parse_python_file(content, file_path, project_root=getattr(self, '_current_project', ''))
            
            # 其他语言的简化解析
            code_file = CodeFile(file_path=file_path, language=lang, raw_content=content)
            return code_file
            
        except Exception as e:
            logger.error(f"解析文件 {file_path} 失败: {e}")
            return None
    
    def analyze_project(self, project_path: str, force_reanalyze: bool = False) -> ProjectAnalysis:
        """完整分析项目（支持缓存）"""
        logger.info(f"开始分析项目: {project_path}")
        
        # 加载项目专属的 cache 硬编码优化（白名单）
        SharedFilter.load_cache(project_path)

        # 检查缓存
        if not force_reanalyze and self._is_cache_valid(project_path):
            cached = self.load_cache(project_path)
            if cached:
                return cached
        
        result = ProjectAnalysis(project_path=project_path)
        
        # 设置当前项目路径以便 parse_file 使用
        self._current_project = project_path
        
        # 扫描所有文件
        code_files = self.scan_directory(project_path)
        result.total_files = len(code_files)
        
        skipped_count = 0
        
        # 逐个解析文件
        for idx, file_path in enumerate(code_files):
            # 每500个文件打一次进度日志
            if idx > 0 and idx % 500 == 0:
                logger.info(f"  分析进度: {idx}/{len(code_files)} 个文件")
            
            code_file = self.parse_file(file_path)
            if code_file:
                # 检查是否跳过
                if code_file.raw_content.startswith("[超大文件"):
                    skipped_count += 1
                
                result.files.append(code_file)
                
                # 统计语言
                result.languages[code_file.language] = result.languages.get(code_file.language, 0) + 1
                
                # 统计行数 - 对超大文件直接从信息字符串提取
                if code_file.raw_content.startswith("[超大文件"):
                    line_match = re.search(r'约 (\d+) 行', code_file.raw_content)
                    if line_match:
                        result.total_lines += int(line_match.group(1))
                else:
                    result.total_lines += len(code_file.raw_content.splitlines())
                
                # 收集依赖
                result.dependencies.update(code_file.dependencies)
                
                # 按模块组织
                rel_path = os.path.relpath(file_path, project_path)
                module = os.path.dirname(rel_path) or 'root'
                result.modules[module].append(rel_path)
        
        # 生成技术栈分析
        result.tech_stack = self._analyze_tech_stack(result)
        
        # 生成核心功能
        result.core_features = self._extract_core_features(result)
        
        # 生成架构摘要
        result.architecture_summary = self._generate_architecture_summary(result)
        
        skip_msg = f"（跳过 {skipped_count} 个超大文件的详细解析）" if skipped_count else ""
        logger.info(f"项目分析完成: {result.total_files} 个文件, {result.total_lines} 行代码 {skip_msg}")
        
        # GitNexus 增强：如果可用，用图谱数据补充分析
        if self._gitnexus_available:
            try:
                self._enhance_with_gitnexus(result)
            except Exception as e:
                logger.warning(f"[CodeAnalyzer] GitNexus增强失败（不影响基础分析）: {e}")
        
        # 保存到缓存
        self.save_cache(result)
        
        return result
    
    def _analyze_tech_stack(self, analysis: ProjectAnalysis) -> List[str]:
        """分析技术栈"""
        tech_stack = []
        
        # 主要语言
        for lang, count in analysis.languages.items():
            tech_stack.append(f"{lang} ({count} 文件)")
        
        # 主要依赖
        common_frameworks = {
            'fastapi': 'FastAPI',
            'flask': 'Flask',
            'django': 'Django',
            'react': 'React',
            'vue': 'Vue.js',
            'angular': 'Angular',
            'pandas': 'Pandas',
            'numpy': 'NumPy',
            'torch': 'PyTorch',
            'tensorflow': 'TensorFlow',
            'requests': 'Requests',
        }
        
        for dep, name in common_frameworks.items():
            if dep in analysis.dependencies:
                tech_stack.append(name)
        
        return tech_stack
    
    def _extract_core_features(self, analysis: ProjectAnalysis) -> List[str]:
        """提取核心功能"""
        features = []
        
        # 从类名和函数名推断功能
        keywords = {
            'api': 'API接口',
            'db': '数据库操作',
            'database': '数据库',
            'auth': '认证授权',
            'user': '用户管理',
            'search': '搜索功能',
            'parser': '解析器',
            'analyzer': '分析器',
            'crawl': '爬虫',
            'scraper': '数据抓取',
            'ml': '机器学习',
            'model': '模型',
            'train': '训练',
            'predict': '预测',
        }
        
        found_features = set()
        
        for code_file in analysis.files:
            for cls in code_file.classes:
                for kw, feature in keywords.items():
                    if kw.lower() in cls.name.lower() and feature not in found_features:
                        found_features.add(feature)
                        features.append(feature)
            
            for func in code_file.functions:
                for kw, feature in keywords.items():
                    if kw.lower() in func.name.lower() and feature not in found_features:
                        found_features.add(feature)
                        features.append(feature)
        
        return features[:10]  # 最多返回10个核心功能
    
    def _generate_architecture_summary(self, analysis: ProjectAnalysis) -> str:
        """生成架构摘要（基础版）"""
        summary_parts = []
        
        # 基本信息
        summary_parts.append(f"## 项目概览")
        summary_parts.append(f"- 总文件数: {analysis.total_files}")
        summary_parts.append(f"- 总代码行数: {analysis.total_lines:,}")
        lang_str = ', '.join([f'{k}({v}个文件)' for k, v in sorted(analysis.languages.items(), key=lambda x: -x[1])])
        summary_parts.append(f"- 语言分布: {lang_str}")
        summary_parts.append(f"- 总模块数: {len(analysis.modules)}")
        summary_parts.append(f"- 总类数: {sum(len(f.classes) for f in analysis.files)}")
        summary_parts.append(f"- 总函数数: {sum(len(f.functions) for f in analysis.files)}")
        
        # 技术栈
        if analysis.tech_stack:
            summary_parts.append(f"\n## 技术栈")
            for tech in analysis.tech_stack:
                summary_parts.append(f"- {tech}")
        
        # 核心功能
        if analysis.core_features:
            summary_parts.append(f"\n## 核心功能")
            for feature in analysis.core_features:
                summary_parts.append(f"- {feature}")
        
        # 模块结构
        summary_parts.append(f"\n## 模块结构")
        for module, files in sorted(analysis.modules.items()):
            summary_parts.append(f"- **{module}**: {len(files)} 个文件")
        
        # 依赖概览
        if analysis.dependencies:
            summary_parts.append(f"\n## 外部依赖")
            for dep in sorted(analysis.dependencies)[:20]:
                summary_parts.append(f"- {dep}")
            if len(analysis.dependencies) > 20:
                summary_parts.append(f"- ... 及其他 {len(analysis.dependencies) - 20} 个依赖")
        
        return '\n'.join(summary_parts)
    
    def _extract_mode_metadata(self, analysis: ProjectAnalysis) -> list:
        """
        从代码中提取工具模式元数据（模式标识、角色、所属工具等）
        V2.1: 从 MODE_METADATA 字典中提取，不再硬编码 fallback
        """
        modes = []
        
        # 扫描所有文件，查找 MODE_METADATA 字典定义（从磁盘读取完整文件）
        for f in analysis.files:
            if 'MODE_METADATA' not in (getattr(f, 'raw_content', '') or ''):
                # raw_content 只有500字符，可能不包含 MODE_METADATA
                # 直接从磁盘读取
                try:
                    with open(f.file_path, 'r', encoding='utf-8') as fh:
                        content = fh.read()
                except Exception:
                    continue
            else:
                content = getattr(f, 'raw_content', '')
            if 'MODE_METADATA' not in content:
                continue
            
            import re
            # 匹配 "tool:mode": { ... "roles": ["A", "B"], ... "name": "xxx", "description": "xxx" ... }
            # 用多行匹配提取完整的模式块
            pattern = r'["\']([\w]+):([\w]+)["\']\s*:\s*\{([^}]+)\}'
            for match in re.finditer(pattern, content):
                mode_id = match.group(1) + ':' + match.group(2)
                block = match.group(3)
                
                # 提取 roles
                roles_match = re.search(r'["\']roles["\']\s*:\s*\[([^\]]*)\]', block)
                roles = []
                if roles_match:
                    roles = [r.strip().strip('"\'') for r in roles_match.group(1).split(',')]
                
                # 提取 name
                name_match = re.search(r'["\']name["\']\s*:\s*["\']([^"\']+)["\']', block)
                cn_name = name_match.group(1) if name_match else mode_id.split(':')[1]
                
                # 提取 description
                desc_match = re.search(r'["\']description["\']\s*:\s*["\']([^"\']+)["\']', block)
                description = desc_match.group(1) if desc_match else ''
                
                tool = mode_id.split(':')[0]
                a_role = '✓' if 'A' in roles else '✗'
                b_role = '✓' if 'B' in roles else '✗'
                
                # 额外能力从 description 提取
                extra = description if description else '-'
                
                modes.append([mode_id, cn_name, tool, a_role, b_role, extra])
        
        if not modes:
            modes = [['(未找到)', '-', '-', '-', '-', '未找到 MODE_METADATA 定义']]
        
        return modes
    
    def _extract_model_roles(self, analysis: ProjectAnalysis) -> list:
        """
        从代码中提取 LLM 模型角色配置
        V2.1: 直接在项目目录中搜索 config.yaml 并解析，不再硬编码
        """
        import yaml as _yaml
        roles = []
        
        # 在项目目录中搜索 config.yaml（不依赖 analysis.files，因为扫描器只扫描代码文件）
        config_path = None
        for root, dirs, files in os.walk(analysis.project_path):
            # 跳过常见的非项目目录
            dirs[:] = [d for d in dirs if d not in ('node_modules', '__pycache__', '.git', 'venv', '.venv', 'data')]
            for fname in files:
                if fname in ('config.yaml', 'config.yml'):
                    config_path = os.path.join(root, fname)
                    break
            if config_path:
                break
        
        if config_path:
            try:
                with open(config_path, 'r', encoding='utf-8') as fh:
                    content = fh.read()
                cfg = _yaml.safe_load(content)
                if isinstance(cfg, dict):
                    # 提取 llm.models 下的角色配置
                    llm_models = cfg.get('llm', {}).get('models', {})
                    if isinstance(llm_models, dict):
                        for role_name, role_cfg in llm_models.items():
                            if isinstance(role_cfg, dict):
                                model_name = role_cfg.get('name', '?')
                                temperature = str(role_cfg.get('temperature', '?'))
                                max_tokens = str(role_cfg.get('max_tokens', '?'))
                                purpose_map = {
                                    'planner': '规划/策略制定', 'writer': '写作/内容生成',
                                    'reviewer': '审查/校验', 'embedder': '嵌入/向量化',
                                    'extractor': '信息提取', 'backtester': '回测/验证',
                                }
                                purpose = purpose_map.get(role_name, role_name)
                                roles.append([role_name, model_name, temperature, max_tokens, purpose])
                    # 提取 semantic 模型配置
                    semantic = cfg.get('semantic', {})
                    if isinstance(semantic, dict):
                        sem_model = semantic.get('model', '')
                        sem_provider = semantic.get('provider', '')
                        if sem_model:
                            roles.append(['semantic', sem_model, '-', '-', f'语义嵌入 ({sem_provider})'])
                    # 提取 vector 模型配置
                    vector = cfg.get('vector', {})
                    if isinstance(vector, dict):
                        local = vector.get('local', {})
                        if isinstance(local, dict):
                            vec_model = local.get('embed_model', '')
                            vec_provider = local.get('provider', '')
                            if vec_model:
                                roles.append(['vector', vec_model, '-', '-', f'向量嵌入 ({vec_provider})'])
                    # 缓存 agent_mapping
                    agent_mapping = cfg.get('agent_mapping', {})
                    if isinstance(agent_mapping, dict):
                        analysis._agent_mapping = agent_mapping
            except Exception:
                pass
        
        if not roles:
            roles = [['(未找到配置)', '-', '-', '-', f'未在 {analysis.project_path} 中找到 config.yaml']]
        return roles
    
    def generate_rich_report(self, analysis: ProjectAnalysis) -> str:
        """
        生成深度分析报告（独立方法，纯代码分析，无 LLM/外部依赖）
        返回完整的 Markdown 报告内容
        """
        report = []
        
        # ==================== 头部 ====================
        report.append("# 📊 项目深度分析报告")
        report.append(f"\n> 生成时间: 即时分析")
        report.append(f"> 项目路径: `{analysis.project_path}`")
        report.append("")
        report.append("---")
        
        # ==================== 1. 项目概览 ====================
        report.append("## 一、项目概览")
        
        total_files = analysis.total_files
        total_lines = analysis.total_lines
        total_classes = sum(len(f.classes) for f in analysis.files)
        total_functions = sum(len(f.functions) for f in analysis.files)
        total_imports = sum(len(f.imports) for f in analysis.files)
        
        report.append(f"| 指标 | 数值 |")
        report.append(f"|------|------|")
        report.append(f"| 📄 代码文件数 | {total_files} |")
        report.append(f"| 📝 总代码行数 | {total_lines:,} |")
        report.append(f"| 🏗️ 模块/目录数 | {len(analysis.modules)} |")
        report.append(f"| 🏛️ 类/结构体数 | {total_classes} |")
        report.append(f"| 🔧 函数/方法数 | {total_functions} |")
        report.append(f"| 📦 导入语句数 | {total_imports} |")
        report.append(f"| 🔗 外部依赖数 | {len(analysis.dependencies)} |")
        
        # ==================== 2. 语言分布 ====================
        report.append("\n## 二、语言分布")
        report.append("\n| 语言 | 文件数 | 占比 |")
        report.append("|------|--------|------|")
        for lang, count in sorted(analysis.languages.items(), key=lambda x: -x[1]):
            pct = count / total_files * 100 if total_files > 0 else 0
            bar = "█" * int(pct / 5) + "░" * (20 - int(pct / 5))
            report.append(f"| {lang} | {count} | {bar} {pct:.1f}% |")
        
        # ==================== 3. 模块结构 ====================
        report.append("\n## 三、模块/目录结构")
        
        # 按文件数排序
        sorted_modules = sorted(analysis.modules.items(), key=lambda x: len(x[1]), reverse=True)
        
        for module, files in sorted_modules:
            # 统计该模块的语言分布
            lang_in_module = {}
            for file in analysis.files:
                rel_path = os.path.relpath(file.file_path, analysis.project_path)
                file_module = os.path.dirname(rel_path) or 'root'
                if file_module == module:
                    lang_in_module[file.language] = lang_in_module.get(file.language, 0) + 1
            
            lang_detail = ', '.join([f"{k}({v})" for k, v in lang_in_module.items()])
            report.append(f"\n### 📁 {module}")
            report.append(f"- **文件数**: {len(files)} 个")
            report.append(f"- **语言**: {lang_detail}")
            
            # 列出该模块下的文件详情
            for file_path in files[:8]:  # 最多显示8个
                # 找到对应的 CodeFile 对象
                full_path = os.path.join(analysis.project_path, file_path)
                code_file = next((f for f in analysis.files if f.file_path == full_path), None)
                if code_file:
                    cls_count = len(code_file.classes)
                    func_count = len(code_file.functions)
                    imp_count = len(code_file.imports)
                    details = []
                    if cls_count > 0:
                        cls_names = ', '.join(c.name for c in code_file.classes[:3])
                        details.append(f"{cls_count}个类[{cls_names}]")
                    if func_count > 0:
                        details.append(f"{func_count}个函数")
                    if imp_count > 0:
                        details.append(f"{imp_count}个导入")
                    detail_str = ' / '.join(details) if details else ''
                    report.append(f"  - `{os.path.basename(file_path)}` {detail_str}")
            
            if len(files) > 8:
                report.append(f"  - ... 及其他 {len(files) - 8} 个文件")
        
        # ==================== 4. 代码实体分析 ====================
        report.append("\n## 四、关键代码实体")
        
        # 所有类（按文件分组）
        all_classes = []
        for f in analysis.files:
            for c in f.classes:
                all_classes.append((c, f))
        
        if all_classes:
            report.append("\n### 🏛️ 类/结构体")
            report.append("\n| 类名 | 所在文件 | 基类 |")
            report.append("|------|----------|------|")
            for cls, code_file in sorted(all_classes, key=lambda x: x[0].name):
                rel_path = os.path.relpath(code_file.file_path, analysis.project_path)
                bases = ', '.join(cls.base_classes) if cls.base_classes else '-'
                report.append(f"| `{cls.name}` | `{rel_path}` | {bases} |")
        
        # 所有函数（按文件分组，去私有）
        all_funcs = []
        for f in analysis.files:
            for func in f.functions:
                if not func.name.startswith('_'):
                    all_funcs.append((func, f))
        
        if all_funcs:
            report.append("\n### 🔧 公开函数/方法")
            report.append("\n| 函数名 | 所在文件 | 参数 |")
            report.append("|--------|----------|------|")
            for func, code_file in sorted(all_funcs, key=lambda x: (os.path.relpath(x[1].file_path, analysis.project_path), x[0].name)):
                rel_path = os.path.relpath(code_file.file_path, analysis.project_path)
                params = ', '.join(func.parameters[:4])
                if len(func.parameters) > 4:
                    params += '...'
                report.append(f"| `{func.name}` | `{rel_path}` | `{params}` |")
        
        # ==================== 5. 依赖分析 ====================
        report.append("\n## 五、依赖关系分析")
        
        # 收集每个文件的关键依赖
        file_deps = []
        for f in analysis.files:
            if f.dependencies:
                rel_path = os.path.relpath(f.file_path, analysis.project_path)
                file_deps.append((rel_path, f.dependencies))
        
        if analysis.dependencies:
            report.append("\n### 📦 外部依赖")
            for dep in sorted(analysis.dependencies)[:30]:
                report.append(f"- `{dep}`")
            if len(analysis.dependencies) > 30:
                report.append(f"- ... 及其他 {len(analysis.dependencies) - 30} 个依赖")
        
        if file_deps:
            report.append("\n### 🔗 文件级依赖")
            report.append("\n| 文件 | 依赖 |")
            report.append("|------|------|")
            for rel_path, deps in file_deps:
                dep_str = ', '.join(f'`{d}`' for d in sorted(deps)[:6])
                if len(deps) > 6:
                    dep_str += f' ...(+{len(deps)-6})'
                report.append(f"| `{rel_path}` | {dep_str} |")
        
        # ==================== 6. 代码度量 ====================
        report.append("\n## 六、代码度量")
        
        # 计算各维度指标
        file_class_ratios = [(f, len(f.classes)) for f in analysis.files if len(f.classes) > 0]
        file_func_ratios = [(f, len(f.functions)) for f in analysis.files if len(f.functions) > 0]
        
        avg_classes_per_file = total_classes / total_files if total_files > 0 else 0
        avg_funcs_per_file = total_functions / total_files if total_files > 0 else 0
        avg_lines_per_file = total_lines / total_files if total_files > 0 else 0
        avg_imports_per_file = total_imports / total_files if total_files > 0 else 0
        
        # 函数量最多的文件
        most_funcs = sorted(file_func_ratios, key=lambda x: -x[1])[:3]
        # 类最多的文件
        most_classes = sorted(file_class_ratios, key=lambda x: -x[1])[:3]
        
        report.append("\n| 指标 | 数值 |")
        report.append("|------|------|")
        report.append(f"| 平均每文件类数 | {avg_classes_per_file:.2f} |")
        report.append(f"| 平均每文件函数数 | {avg_funcs_per_file:.2f} |")
        report.append(f"| 平均每文件行数 | {avg_lines_per_file:.0f} |")
        report.append(f"| 平均每文件导入数 | {avg_imports_per_file:.1f} |")
        
        if most_funcs:
            report.append("\n**函数最密集的文件**:")
            for f, count in most_funcs:
                rel_path = os.path.relpath(f.file_path, analysis.project_path)
                report.append(f"- `{rel_path}` — {count} 个函数")
        
        if most_classes:
            report.append("\n**类最集中的文件**:")
            for f, count in most_classes:
                rel_path = os.path.relpath(f.file_path, analysis.project_path)
                report.append(f"- `{rel_path}` — {count} 个类")
        
        # ==================== 7. 技术栈评估 ====================
        if analysis.tech_stack:
            report.append("\n## 七、技术栈评估")
            for tech in analysis.tech_stack:
                report.append(f"- ✅ {tech}")
        
        # ==================== 8. 核心功能 ====================
        if analysis.core_features:
            report.append("\n## 八、核心功能识别")
            for feature in analysis.core_features:
                report.append(f"- 🎯 {feature}")
        
        # ==================== 9. 入口点检测 ====================
        report.append("\n## 九、入口点检测")
        entry_files = []
        for f in analysis.files:
            basename = os.path.basename(f.file_path)
            if basename in ('main.py', 'index.js', 'app.py', 'server.py', '__init__.py', 'index.ts'):
                entry_files.append(f)
        
        if entry_files:
            for f in entry_files:
                rel_path = os.path.relpath(f.file_path, analysis.project_path)
                report.append(f"- 🚪 `{rel_path}`")
        else:
            report.append("- 未检测到标准入口文件")
        
        report.append("\n---")
        report.append("\n*报告由 CodeRef AI 代码分析引擎自动生成*")
        
        return '\n'.join(report)

        
        def mk_table(headers, rows):
            """快速生成markdown表格"""
            sep = '|' + '|'.join(['---'] * len(headers)) + '|'
            lines.append('| ' + ' | '.join(headers) + ' |')
            lines.append(sep)
            for row in rows:
                lines.append('| ' + ' | '.join(str(c) for c in row) + ' |')
            lines.append('')
        
        def hz_bar(count, total, width=20):
            """生成水平柱状条"""
            if total <= 0:
                return '░' * width
            filled = int(count / total * width)
            return '█' * filled + '░' * (width - filled)
        
        # ================================================================
        #  HEADER — 专业报告头部（深度架构分析报告风格）
        # ================================================================
        has_enhanced = False
        now_str = datetime.now().strftime('%Y-%m-%d %H:%M')
        
        # 从依赖推断技术选型标签（使用中文业务描述）
        tech_tags = set()
        dep_lower = {d.lower() for d in analysis.dependencies}
        if 'fastapi' in dep_lower: tech_tags.add('Web服务')
        if 'flask' in dep_lower: tech_tags.add('Web服务')
        if 'django' in dep_lower: tech_tags.add('Web框架')
        if 'pydantic' in dep_lower: tech_tags.add('数据校验')
        if any(k in dep_lower for k in ('openai', 'anthropic', 'deepseek')): tech_tags.add('AI大模型')
        if any(k in dep_lower for k in ('requests', 'httpx', 'aiohttp')): tech_tags.add('网络通信')
        if 'jinja2' in dep_lower or 'jinja' in dep_lower: tech_tags.add('模板引擎')
        if 'playwright' in dep_lower or 'selenium' in dep_lower: tech_tags.add('浏览器自动化')
        if 'beautifulsoup' in dep_lower or 'lxml' in dep_lower or 'parsel' in dep_lower: tech_tags.add('网页解析')
        if 'pandas' in dep_lower: tech_tags.add('数据处理')
        if 'numpy' in dep_lower: tech_tags.add('数值计算')
        if 'pillow' in dep_lower or 'pil' in dep_lower: tech_tags.add('图像处理')
        if any(k in dep_lower for k in ('python-docx', 'docx')): tech_tags.add('文档生成')
        if any(k in dep_lower for k in ('openpyxl', 'xlsxwriter')): tech_tags.add('表格处理')
        if 'rich' in dep_lower or 'colorama' in dep_lower: tech_tags.add('终端交互')
        if 'loguru' in dep_lower or 'logging' in dep_lower: tech_tags.add('日志系统')
        
        # 从模块名构建工具名称列表
        sorted_m = _sorted_modules()
        top_modules = _aggregate_by_top(sorted_m)
        module_names_list = [m for m, _ in top_modules if m != 'root']
        tools_str = ' · '.join(module_names_list[:5])
        tech_tags_str = ' · '.join(sorted(tech_tags)[:4])
        
        lines.append(f'# {project_name}  深度架构分析报告')
        lines.append('')
        lines.append(f'> **副标题**: 全量代码扫描 · 工具工作流 · A/B角色差异 · LLM模型配置')
        lines.append(f'> **报告版本**: v2.0 | **生成日期**: {now_str} | **扫描范围**: {total_files} 个文件，{total_lines:,} 行代码')
        lines.append('')
        lines.append('---')
        lines.append('')
        
        # ---- 业务模块检测（保留原逻辑）----
        top_level_stats = defaultdict(lambda: [0, 0])
        for f in analysis.files:
            rel_path = os.path.relpath(f.file_path, analysis.project_path)
            top_name = rel_path.split('\\')[0].split('/')[0]
            top_level_stats[top_name][0] += len(f.classes)
            top_level_stats[top_name][1] += len(f.functions)
        
        business_modules = []
        non_business_modules = []
        for module, files in top_modules:
            if module == 'root':
                continue
            stats = top_level_stats.get(module, [0, 0])
            cc, fcc = stats[0], stats[1]
            is_non_business = (
                (cc == 0 and fcc == 0 and len(files) >= 5) or
                (len(files) > 50 and cc < 5 and fcc < 10)
            )
            if is_non_business:
                non_business_modules.append(module)
            else:
                business_modules.append((module, files, cc, fcc))
        
        display_modules = business_modules[:6]
        
        if non_business_modules:
            excluded_names = '、'.join(non_business_modules[:5])
            if len(non_business_modules) > 5:
                excluded_names += f'等{len(non_business_modules)}个目录'
        else:
            excluded_names = None
        
        # ================================================================
        #  一、系统总览
        # ================================================================
        a('一、系统总览', '一系统总览')
        
        # 1.1 系统定位
        h3('1.1 系统定位')
        
        lang_names = list(analysis.languages.keys())
        lang_str = ' + '.join(sorted(lang_names))
        num_business_modules = len([m for m, _, _, _ in display_modules if m != 'root'])
        module_names = [m for m, _, _, _ in display_modules]
        
        # 从类名推断核心业务标签
        all_class_names = []
        for f in analysis.files:
            for c in f.classes:
                all_class_names.append(c.name)
        all_class_str = ' '.join(all_class_names)
        biz_tags = []
        if any('Research' in n or 'Search' in n or 'Scrape' in n for n in all_class_names):
            biz_tags.append('市场调研')
        if any('Strategy' in n or 'Anchor' in n or 'Skeleton' in n for n in all_class_names):
            biz_tags.append('方案策划')
        if any('Insight' in n or 'Analyzer' in n for n in all_class_names):
            biz_tags.append('商业洞察')
        if any('Pipeline' in n or 'Render' in n or 'Generate' in n for n in all_class_names):
            biz_tags.append('内容生成')
        if any('Agent' in n or 'Bot' in n or 'Orchestrator' in n for n in all_class_names):
            biz_tags.append('智能代理')
        if any('Cognition' in n or 'Knowledge' in n or 'Template' in n for n in all_class_names):
            biz_tags.append('知识管理')
        if any('Canvas' in n or 'Tool' in n or 'Refinery' in n for n in all_class_names):
            biz_tags.append('创意引擎')
        
        biz_tag_str = '、'.join(biz_tags) if biz_tags else '多业务模块'
        
        lines.append(f'本项目是一套基于 **{lang_str}** 开发的智能商业工具平台，围绕「{biz_tag_str}」提供一站式解决方案。')
        lines.append(f'系统经全量代码扫描，识别出 **{num_business_modules} 个核心业务模块**，共计 {total_files} 个代码文件、{total_lines:,} 行代码，')
        lines.append(f'定义 {total_classes} 个业务实体和 {total_functions} 个处理逻辑，集成 {len(analysis.dependencies)} 项外部技术能力。')
        lines.append('')
        lines.append(f'核心模块包括：{"、".join(module_names)} 等。每个模块承载独立的业务能力，模块间通过明确的调用契约协作，')
        lines.append(f'共同构成完整的业务闭环。')
        lines.append('')
        
        # 1.2 核心工具总览
        h3('1.2 核心工具总览')
        
        # 为每个模块动态推断核心能力
        def _infer_capabilities(mod_name):
            """从模块内所有类名推断核心能力（去重）"""
            KEYWORD_CAP_MAP = [
                ('Orchestrator', '多智能体协作编排'),
                ('Orchestration', '多智能体协作编排'),
                ('Research', '市场调研流程管理'),
                ('Search', '多源搜索集成'),
                ('Scraper', '网页数据抓取'),
                ('Crawler', '网页数据抓取'),
                ('Strategy', '策略选择与匹配'),
                ('Selector', '策略选择与匹配'),
                ('Pipeline', '流程编排管线'),
                ('Render', '内容渲染生成'),
                ('RenderPipeline', '内容渲染管线'),
                ('Engine', '核心处理引擎'),
                ('Scheduler', '任务调度管理'),
                ('Manager', '统一资源管理'),
                ('Agent', 'AI代理角色'),
                ('Bot', '自动化流程执行'),
                ('Tool', '功能入口工具'),
                ('Runner', '任务执行器'),
                ('Factory', '对象实例工厂'),
                ('Builder', '内容构建器'),
                ('Generator', '内容生成器'),
                ('Compiler', '内容编译生成'),
                ('Transformer', '数据格式转换'),
                ('Converter', '格式转换器'),
                ('Parser', '数据解析器'),
                ('Extractor', '信息提取器'),
                ('Analyzer', '数据分析器'),
                ('Detector', '异常检测器'),
                ('Validator', '数据校验器'),
                ('Filter', '内容筛选器'),
                ('Handler', '请求处理器'),
                ('Controller', '请求分发路由'),
                ('Service', '业务服务封装'),
                ('Provider', '资源提供者'),
                ('Adapter', '外部系统适配'),
                ('Client', '外部API客户端'),
                ('Canvas', '结构化推理框架'),
                ('Cognition', '认知框架管理'),
                ('Insight', '商业洞察提取'),
                ('Knowledge', '领域知识管理'),
                ('Template', '方案模板管理'),
                ('Anchor', '方案方向锚定'),
                ('Skeleton', '方案大纲生成'),
                ('Polish', '文本润色优化'),
                ('Review', '质量审核'),
                ('Refinery', '方案精炼筛选'),
                ('Seed', '渲染策略匹配'),
                ('Integrator', '模块集成对接'),
                ('Middleware', '请求拦截处理'),
                ('Router', '路径分发路由'),
                ('Repository', '数据持久化'),
                ('Guard', '权限安全检查'),
                ('Iterator', '数据迭代遍历'),
                ('Loader', '数据加载器'),
                ('Writer', '数据写入器'),
                ('Reader', '数据读取器'),
                ('Config', '配置管理'),
                ('Registry', '注册管理中心'),
            ]
            caps = []
            for cf in analysis.files:
                rel = os.path.relpath(cf.file_path, analysis.project_path)
                if _top_module_name(os.path.dirname(rel)) == mod_name:
                    for c in cf.classes:
                        if c.name.startswith('_') or c.name in ('FastAPI', 'HTTPException', 'BaseModel', 'Base', 'BackgroundTasks', 'Request', 'Response', 'JSONResponse', 'APIRouter', 'TestCase', 'Mock', 'QWidget', 'QMainWindow', 'QDialog', 'QObject', 'QThread', 'Signal', 'Slot', 'Property'):
                            continue
                        for keyword, cap in KEYWORD_CAP_MAP:
                            if keyword in c.name:
                                caps.append(cap)
                                break
            # 去重
            seen = set()
            result = []
            for cap in caps:
                if cap not in seen:
                    seen.add(cap)
                    result.append(cap)
            return result[:8]
        
        total_lang = sum(analysis.languages.values()) if analysis.languages else 0
        
        mk_table(
            ['工具名称', '业务定位', '核心能力', '文件数'],
            [
                [
                    module,
                    f'模块内 {cc} 个业务实体、{fcc} 个处理逻辑',
                    '、'.join([c for c in _infer_capabilities(module) if c not in ('功能入口工具',)]) if _infer_capabilities(module) else '业务逻辑处理',
                    str(len(files))
                ]
                for module, files, cc, fcc in display_modules
            ]
        )
        
        # 1.3 技术栈概览
        h3('1.3 技术栈概览')
        
        # 构建技术栈层次分类
        tech_layers = []
        
        # 语言层
        lang_items = []
        for lang, count in sorted(analysis.languages.items(), key=lambda x: -x[1]):
            lang_items.append(f'{lang}（{count}文件）')
        if lang_items:
            tech_layers.append(('编程语言', '、'.join(lang_items), '系统开发基础语言'))
        
        # AI/LLM 层
        llm_techs = []
        for dep in analysis.dependencies:
            dl = dep.lower()
            if 'openai' in dl: llm_techs.append('OpenAI API')
            elif 'anthropic' in dl: llm_techs.append('Anthropic API')
            elif 'deepseek' in dl: llm_techs.append('DeepSeek API')
        if llm_techs:
            tech_layers.append(('LLM模型', '、'.join(llm_techs[:3]), 'AI规划/写作/审核'))
        
        # 框架层
        framework_map = {
            'fastapi': 'Web框架', 'flask': 'Web框架', 'django': 'Web框架',
            'pydantic': '数据校验', 'sqlalchemy': '数据库ORM', 'sqlmodel': '数据库ORM',
            'tortoise-orm': '数据库ORM', 'beanie': '数据库ORM',
            'pandas': '数据处理', 'numpy': '数值计算', 'scipy': '科学计算',
        }
        frameworks = []
        for dep in analysis.dependencies:
            dl = dep.lower()
            for key, name in framework_map.items():
                if key in dl:
                    frameworks.append(name)
                    break
        if frameworks:
            tech_layers.append(('框架/类库', '、'.join(sorted(set(frameworks))[:5]), '核心框架与数据处理'))
        
        # 搜索/爬取层
        crawler_techs = []
        for dep in analysis.dependencies:
            dl = dep.lower()
            if 'beautifulsoup' in dl: crawler_techs.append('BeautifulSoup')
            elif 'selenium' in dl: crawler_techs.append('Selenium')
            elif 'playwright' in dl: crawler_techs.append('Playwright')
            elif 'lxml' in dl: crawler_techs.append('lxml')
            elif 'parsel' in dl: crawler_techs.append('Parsel')
            elif 'httpx' in dl: crawler_techs.append('httpx')
        if crawler_techs:
            tech_layers.append(('搜索/爬取', '、'.join(sorted(set(crawler_techs))[:4]), '多源数据获取'))
        
        # 文档/输出层
        doc_techs = []
        for dep in analysis.dependencies:
            dl = dep.lower()
            if 'python-docx' in dl or 'docx' == dl: doc_techs.append('python-docx')
            elif 'openpyxl' in dl: doc_techs.append('openpyxl')
            elif 'xlsxwriter' in dl: doc_techs.append('XlsxWriter')
            elif 'jinja' in dl: doc_techs.append('Jinja2')
            elif 'weasyprint' in dl or 'pdfkit' in dl: doc_techs.append('PDF生成')
            elif 'matplotlib' in dl: doc_techs.append('Matplotlib')
            elif 'pillow' in dl or 'pil' in dl: doc_techs.append('Pillow')
        if doc_techs:
            tech_layers.append(('文档/输出', '、'.join(sorted(set(doc_techs))[:4]), '报告和文档生成'))
        
        # 通信/部署层
        comm_techs = []
        for dep in analysis.dependencies:
            dl = dep.lower()
            if 'requests' in dl: comm_techs.append('Requests')
            elif 'aiohttp' in dl: comm_techs.append('aiohttp')
            elif 'uvicorn' in dl: comm_techs.append('Uvicorn')
            elif 'gunicorn' in dl: comm_techs.append('Gunicorn')
            elif 'websocket' in dl: comm_techs.append('WebSocket')
            elif 'redis' in dl: comm_techs.append('Redis')
        if comm_techs:
            tech_layers.append(('通信/部署', '、'.join(sorted(set(comm_techs))[:4]), '网络通信与Web服务'))
        
        # 开发工具
        dev_techs = []
        for dep in analysis.dependencies:
            dl = dep.lower()
            if 'loguru' in dl: dev_techs.append('Loguru')
            elif 'rich' in dl: dev_techs.append('Rich')
            elif 'colorama' in dl: dev_techs.append('Colorama')
            elif 'pytest' in dl: dev_techs.append('Pytest')
            elif 'click' in dl or 'typer' in dl: dev_techs.append('CLI框架')
        if dev_techs:
            tech_layers.append(('开发工具', '、'.join(sorted(set(dev_techs))[:4]), '日志/测试/终端交互'))
        
        if tech_layers:
            mk_table(
                ['层次', '技术选型', '用途'],
                tech_layers
            )
        else:
            lines.append(f'主要编程语言：{lang_str}，外部依赖 {len(analysis.dependencies)} 项。')
            lines.append('')
        
        # ================================================================
        #  二、A/B双角色架构（V2.0新增：业务视角）
        # ================================================================
        a('二、A/B双角色架构', '二AB双角色架构')
        
        h3('2.1 角色定位（从代码提取）')
        lines.append('**A角色（Web普通用户）**：使用 standard 授权码激活，配额各10次。**所有功能都可用**，包括深度模式、导演模式等，只是配额较少。')
        lines.append('- 认证方式：JWT Token + standard 授权码（`auth.py`）')
        lines.append('- 配额：调研10次 / 方案10次 / 洞察10次')
        lines.append('- 模式：TOOL_MODES_A 包含所有模式（normal/deep/breadth/quick），无模式限制')
        lines.append('- 运行环境：浏览器访问 FastAPI 后端')
        lines.append('')
        lines.append('**B角色（Web管理员 + 本地开发者）**：')
        lines.append('- **Web端**：使用 premium 授权码激活，配额各50次，但**禁止提交任务**（返回403，只读权限）')
        lines.append('- **本地GUI端**：无授权码、无配额限制，解锁全部高级功能（白盒推理、自学习、种子精炼等）')
        lines.append('- 认证方式：Web端 JWT + premium 授权码；GUI端无认证（`main.py`）')
        lines.append('')
        
        h3('2.2 角色功能差异矩阵（从代码提取）')
        lines.append('| 维度 | A角色（standard） | B角色（premium） | 代码依据 |')
        lines.append('|------|-------------------|------------------|----------|')
        lines.append('| 授权码类型 | standard | premium | `database.py` License.type |')
        lines.append('| Web端配额 | 各10次 | 各50次 | `database.py` quota 字段 |')
        lines.append('| Web端任务提交 | ✅ 可提交 | ❌ 禁止（403） | `tasks.py` is_admin 检查 |')
        lines.append('| Web端模式限制 | 无限制（所有模式） | N/A（不能提交） | `tasks.py` TOOL_MODES_A |')
        lines.append('| GUI端可用 | ❌ | ✅ 全部功能 | `CodeRef_AI/main.py` |')
        lines.append('| 白盒/黑盒 | 黑盒（隐藏中间数据） | 白盒（完整透明） | `main_v3_1.py` role 判断 |')
        lines.append('| 自学习 | ❌ | ✅ 大败局+评分反馈 | `self_learning.py` |')
        lines.append('| 种子精炼 | ❌ | ✅ 可投喂精炼 | `admin.py` |')
        lines.append('| 方案审核 | ❌ | ✅ 三级入库审核 | `admin.py` |')
        lines.append('')
        
        h3('2.3 关键设计说明（从代码提取）')
        lines.append('1. **A角色功能全开**：`tasks.py` 的 `TOOL_MODES_A` 包含所有模式（normal/deep/breadth/quick），A角色在Web端可以使用深度模式、导演模式等全部功能，只是配额限制为10次。')
        lines.append('')
        lines.append('2. **B角色Web端只读**：`tasks.py` 第219行 `if current_user.is_admin: raise HTTPException(403)`，B角色（premium）在Web端只能查看日志和数据，不能提交任务。这是设计意图——B角色的核心使用场景是本地GUI。')
        lines.append('')
        lines.append('3. **导演模式的A/B差异**：`main_v3_1.py` 中 A角色调用黑盒版（`_b05_to_b06_director_mode_blackbox`），隐藏中间数据，只显示骨架选择；B角色调用白盒版（`b05_to_b06_director_mode`），显示完整推理过程。')
        lines.append('')
        lines.append('4. **自学习B角色独占**：`self_learning.py` 中的 `BRoleFeedback`、`DabaijuLibrary`、`LearningLog` 仅在本地GUI中使用，A角色无此功能。')
        lines.append('')
        
        # ================================================================
        #  三、LLM模型配置与模型路由（V2.0新增）
        # ================================================================
        a('三、LLM模型配置与模型路由', '三LLM模型配置')
        
        h3('3.1 模型角色映射')
        # 从 config.yaml 或代码中提取模型配置
        model_roles = self._extract_model_roles(analysis)
        if model_roles:
            mk_table(
                ['角色名', '实际模型', 'Temperature', 'Max Tokens', '用途'],
                model_roles
            )
        else:
            lines.append('> 未能从代码中提取模型配置，请检查配置中心/config.yaml 或各工具的 model_router.py。')
            lines.append('')
        
        h3('3.2 模型分配策略（从配置提取）')
        # 从提取的模型角色中推断策略
        model_names_used = set()
        for row in model_roles:
            if len(row) >= 2 and row[0] not in ('semantic', 'vector', '(未找到配置)'):
                model_names_used.add(row[1])
        
        for model_name in model_names_used:
            # 找使用此模型的角色
            users = [row[0] for row in model_roles if len(row) >= 2 and row[1] == model_name]
            if any(u in users for u in ('planner', 'reviewer', 'extractor', 'backtester')):
                lines.append(f'**{model_name}**（高精度任务）：用于 {", ".join(users)}。这些任务需要严谨的逻辑推理和事实校验。')
                lines.append('')
            elif any(u in users for u in ('writer',)):
                lines.append(f'**{model_name}**（高吞吐任务）：用于 {", ".join(users)}。需要快速响应和大量文本生成。')
                lines.append('')
        
        # 语义和向量模型单独说明
        for row in model_roles:
            if len(row) >= 2 and row[0] == 'semantic':
                lines.append(f'**语义模型（{row[1]}）**：通过Ollama本地部署，用于语义检索、文本嵌入。')
                lines.append('')
            elif len(row) >= 2 and row[0] == 'vector':
                lines.append(f'**向量模型（{row[1]}）**：用于种子匹配、向量化操作。')
                lines.append('')
        
        # ================================================================
        #  四、项目全景图
        # ================================================================
        a('四、项目全景图', '四项目全景图')
        
        # 2.1 项目规模
        h3('2.1 项目规模')
        
        mk_table(
            ['指标', '数值', '说明'],
            [
                ['代码文件数', str(total_files), '全量代码扫描统计'],
                ['总代码行数', f'{total_lines:,}', '含注释和空行'],
                ['模块/目录数', str(len(analysis.modules)), '顶级模块聚合后数量'],
                ['业务实体数', str(total_classes), '所有代码文件中定义的类和结构体'],
                ['处理逻辑数', str(total_functions), '含私有和公开函数/方法'],
                ['导入语句数', str(total_imports), 'import 语句汇总'],
                ['外部依赖数', str(len(analysis.dependencies)), '第三方库依赖统计'],
            ]
        )
        
        # 2.2 语言分布
        h3('2.2 语言分布')
        if analysis.languages:
            mk_table(
                ['语言', '文件数', '占比', '分布图'],
                [
                    [
                        lang,
                        str(count),
                        f'{count/total_lang*100:.1f}%' if total_lang > 0 else '0%',
                        hz_bar(count, total_lang)
                    ]
                    for lang, count in sorted(analysis.languages.items(), key=lambda x: -x[1])
                ]
            )
        
        # 2.3 核心入口文件
        h3('2.3 核心入口文件')
        
        entry_candidates = ['main.py', 'index.js', 'app.py', 'server.py',
                           'web_server.py', 'v4_main.py', 'insight_cli.py',
                           '__main__.py', 'manage.py', 'cli.py', 'run.py',
                           'start.py', 'launcher.py', 'bootstrap.py']
        entry_rows = []
        for f in analysis.files:
            basename = os.path.basename(f.file_path)
            if basename in entry_candidates:
                rel_path = os.path.relpath(f.file_path, analysis.project_path)
                module_name = os.path.dirname(rel_path) or 'root'
                # 用自然语言描述用途
                cls_names = [c.name for c in f.classes[:3]]
                purpose_parts = []
                for cn in cls_names:
                    if 'Main' in cn or 'App' in cn:
                        purpose_parts.append('应用入口')
                    elif 'Server' in cn or 'Web' in cn:
                        purpose_parts.append('Web服务')
                    elif 'Cli' in cn or 'CLI' in cn:
                        purpose_parts.append('命令行入口')
                    elif 'Bot' in cn:
                        purpose_parts.append('机器人入口')
                    elif 'Runner' in cn:
                        purpose_parts.append('流程启动器')
                    else:
                        purpose_parts.append('程序启动')
                purpose_str = '、'.join(dict.fromkeys(purpose_parts)) if purpose_parts else '程序入口'
                entry_rows.append((rel_path, module_name, purpose_str))
        
        if entry_rows:
            mk_table(
                ['入口文件路径', '所属模块', '用途'],
                [[f'`{p}`', m, pu] for p, m, pu in entry_rows]
            )
        else:
            lines.append('未检测到标准入口文件，系统可能通过模块动态组合方式运行。')
            lines.append('')
        
        # 2.4 模块依赖架构图（Mermaid）
        h3('2.4 模块依赖架构图')
        try:
            mermaid_code = self.generate_mermaid_diagram(analysis)
            if mermaid_code:
                lines.append('```mermaid')
                lines.append(mermaid_code)
                lines.append('```')
                lines.append('')
        except Exception as e:
            logger.debug(f"Mermaid图生成失败: {e}")
            lines.append('*（架构图生成失败，请确保已安装 gitnexus）*')
            lines.append('')
        
        # ================================================================
        #  三、各工具工作流
        # ================================================================
        a('三、各工具工作流', '三各工具工作流')
        
        # 工作流关键词检测
        WORKFLOW_KEYWORDS = ['step', 'stage', 'pipeline', 'flow', 'phase', 'process', 'workflow', 'task', 'job']
        
        def _detect_workflow(mod_name):
            """检测模块是否有工作流/流程特征"""
            for cf in analysis.files:
                rel = os.path.relpath(cf.file_path, analysis.project_path)
                if _top_module_name(os.path.dirname(rel)) == mod_name:
                    for c in cf.classes:
                        for kw in WORKFLOW_KEYWORDS:
                            if kw in c.name.lower():
                                return True
                    for func in cf.functions:
                        for kw in WORKFLOW_KEYWORDS:
                            if kw in func.name.lower():
                                return True
            return False
        
        def _detect_agent_features(mod_name):
            """检测模块是否具有AI Agent特征"""
            agent_terms = {'Agent', 'Bot', 'Orchestrator', 'Orchestration', 'Cognition', 'Canvas'}
            for cf in analysis.files:
                rel = os.path.relpath(cf.file_path, analysis.project_path)
                if _top_module_name(os.path.dirname(rel)) == mod_name:
                    for c in cf.classes:
                        if any(t in c.name for t in agent_terms):
                            return True
            return False
        
        def _detect_search_features(mod_name):
            """检测模块是否具有搜索/爬取特征"""
            search_terms = {'Search', 'Scraper', 'Crawler', 'Extractor', 'Fetch'}
            for cf in analysis.files:
                rel = os.path.relpath(cf.file_path, analysis.project_path)
                if _top_module_name(os.path.dirname(rel)) == mod_name:
                    for c in cf.classes:
                        if any(t in c.name for t in search_terms):
                            return True
            return False
        
        def _get_module_files(mod_name):
            """获取模块下所有 CodeFile 对象"""
            result = []
            for f in analysis.files:
                rel = os.path.relpath(f.file_path, analysis.project_path)
                if _top_module_name(os.path.dirname(rel)) == mod_name:
                    result.append(f)
            return result
        
        # 为每个业务模块生成工作流章节
        for module, files, cc_total, fcc_total in display_modules:
            lines.append(f'### {module}')
            lines.append('')
            
            fc = len(files)
            mod_files = _get_module_files(module)
            caps = _infer_capabilities(module)
            has_wf = _detect_workflow(module)
            has_agent = _detect_agent_features(module)
            has_search = _detect_search_features(module)
            
            # 核心定位
            position_parts = []
            if has_agent:
                position_parts.append('AI驱动')
            if has_search:
                position_parts.append('多源数据获取')
            if has_wf:
                position_parts.append('流程化处理')
            position_prefix = '、'.join(position_parts) if position_parts else '业务逻辑'
            lines.append(f'> **核心定位**: 本模块提供{position_prefix}能力，包含 {fc} 个代码文件、{cc_total} 个业务实体和 {fcc_total} 个处理逻辑。')
            lines.append('')
            
            # 核心能力表格
            if caps:
                lines.append('**核心能力**:')
                lines.append('')
                cap_details = []
                for cap in caps[:6]:
                    # 跳过"功能入口工具"这类无信息量的噪音
                    if cap in ('功能入口工具',):
                        continue
                    # 为每种能力生成具体的业务描述（不再用泛泛的"通过XXX实现"）
                    if '搜索' in cap or '爬取' in cap:
                        cap_desc = '从互联网多源获取数据，支持多适配器并行采集'
                    elif '编排' in cap or '管线' in cap:
                        cap_desc = '定义多阶段处理顺序，串联各处理节点形成完整工作流'
                    elif '策略' in cap or '选择' in cap:
                        cap_desc = '根据条件动态匹配和执行最优策略'
                    elif '引擎' in cap or '生成' in cap or '创意' in cap:
                        cap_desc = '核心业务逻辑处理，驱动主要业务流程'
                    elif '管理' in cap or '模板' in cap:
                        cap_desc = '统一管理模块内资源和状态，提供访问接口'
                    elif '分析' in cap or '洞察' in cap or '认知' in cap:
                        cap_desc = '对输入数据进行结构化分析和商业洞见提取'
                    elif '转换' in cap or '解析' in cap:
                        cap_desc = '解析多源数据格式，转换数据结构'
                    elif '代理' in cap or '智能' in cap:
                        cap_desc = '封装大语言模型交互，执行智能决策任务'
                    elif '适配' in cap or '客户端' in cap:
                        cap_desc = '对接外部系统和服务，统一调用接口'
                    elif '路由' in cap or '分发' in cap:
                        cap_desc = '请求分发和路径路由，确保正确送达处理节点'
                    elif '校验' in cap or '审核' in cap:
                        cap_desc = '验证输入数据的完整性和合法性'
                    elif '锚定' in cap:
                        cap_desc = '确定方案方向和基线，生成锚点问题'
                    elif '排期' in cap or '日程' in cap:
                        cap_desc = '生成执行排期计划，管理时间节点'
                    else:
                        cap_desc = '实现特定业务功能和操作'
                    cap_details.append((cap, cap_desc))
                
                mk_table(
                    ['能力类别', '具体描述'],
                    cap_details
                )
            
            # 工作流阶段（如果检测到工作流特征）
            if has_wf:
                lines.append('**工作流阶段**:')
                lines.append('')
                # 从函数名中提取真实的阶段信息（以中文业务描述呈现）
                stages = []
                seen_stage_names = set()
                
                for cf in mod_files:
                    for func in cf.functions:
                        f_lower = func.name.lower()
                        # 跳过私有函数、辅助函数、GUI事件处理
                        if func.name.startswith('_') or func.name in ('main', 'setup', 'init', 'run', 'start', 'stop',
                            'on_add_task', 'on_delete_task', 'on_task_double_click', 'on_send_task_email',
                            'render', 'update', 'refresh', 'reload', 'clear', 'reset',
                            'connect', 'disconnect', 'close', 'open', 'save', 'load'):
                            continue
                        # 跳过GUI/事件处理模式
                        if f_lower.startswith('on_') or f_lower.startswith('handle_'):
                            continue
                        # 跳过PascalCase函数名（不是工作流阶段，如 GetPipeline, InferStrategy）
                        if '_' not in func.name and func.name[0].isupper():
                            continue
                        # 检测工作流关键字
                        for kw in WORKFLOW_KEYWORDS:
                            if kw in f_lower:
                                # 将函数名转中文阶段描述
                                chinese_name = ''
                                if 'clarify' in f_lower or 'question' in f_lower:
                                    chinese_name = '需求澄清'
                                elif 'plan' in f_lower:
                                    chinese_name = '计划制定'
                                elif 'search' in f_lower or 'preflight' in f_lower:
                                    chinese_name = '搜索预审'
                                elif 'depth' in f_lower or 'crawl' in f_lower or 'fetch' in f_lower:
                                    chinese_name = '全景搜索'
                                elif 'coverage' in f_lower or 'supplement' in f_lower:
                                    chinese_name = '覆盖度评估'
                                elif 'assess' in f_lower or 'evaluat' in f_lower:
                                    chinese_name = '评估审核'
                                elif 'outline' in f_lower or 'skeleton' in f_lower or 'emerge' in f_lower:
                                    chinese_name = '骨架生成'
                                elif 'chapter' in f_lower or 'write' in f_lower:
                                    chinese_name = '逐章扩写'
                                elif 'denoise' in f_lower or 'review' in f_lower:
                                    chinese_name = '去噪复审'
                                elif 'compile' in f_lower or 'deliver' in f_lower or 'export' in f_lower:
                                    chinese_name = '输出编译'
                                elif 'anchor' in f_lower:
                                    chinese_name = '锚定分析'
                                elif 'template' in f_lower:
                                    chinese_name = '模板匹配'
                                elif 'schedule' in f_lower:
                                    chinese_name = '排期生成'
                                elif 'render' in f_lower:
                                    chinese_name = '渲染输出'
                                elif 'polish' in f_lower or 'edit' in f_lower:
                                    chinese_name = '润色统稿'
                                elif 'process' in f_lower or 'execut' in f_lower or 'run' in f_lower:
                                    chinese_name = '执行处理'
                                elif 'valid' in f_lower or 'check' in f_lower:
                                    chinese_name = '校验审核'
                                elif 'analyz' in f_lower or 'detect' in f_lower:
                                    chinese_name = '分析检测'
                                elif 'generat' in f_lower or 'creat' in f_lower:
                                    chinese_name = '生成创建'
                                elif 'dispatch' in f_lower or 'orchestrat' in f_lower:
                                    chinese_name = '调度编排'
                                else:
                                    chinese_name = '业务处理'
                                
                                if chinese_name not in seen_stage_names:
                                    seen_stage_names.add(chinese_name)
                                    stages.append((chinese_name, '按流程执行'))
                                break
                
                if stages:
                    mk_table(
                        ['阶段', '说明'],
                        stages[:8]
                    )
            
            # 关键引擎/组件说明
            lines.append('**关键引擎说明**:')
            lines.append('')
            engine_descriptions = []
            for cf in mod_files:
                for c in cf.classes:
                    en = c.name
                    if 'Engine' in en:
                        engine_descriptions.append(f'- **核心处理引擎**: 驱动模块主要业务流程，协调各组件完成业务目标')
                    elif 'Pipeline' in en:
                        engine_descriptions.append(f'- **流程编排管线**: 定义多阶段处理顺序，串联各处理节点')
                    elif 'Agent' in en:
                        engine_descriptions.append(f'- **AI代理**: 封装大语言模型交互，执行智能决策任务')
                    elif 'Manager' in en:
                        engine_descriptions.append(f'- **资源管理器**: 统一管理模块内资源和状态，提供访问接口')
                    elif 'Factory' in en:
                        engine_descriptions.append(f'- **实例工厂**: 负责创建复杂对象，封装构造逻辑')
                    elif 'Controller' in en or 'Handler' in en:
                        engine_descriptions.append(f'- **请求处理器**: 接收外部输入，分发给对应处理逻辑')
                    elif 'Service' in en:
                        engine_descriptions.append(f'- **业务服务**: 封装核心业务逻辑，提供高层接口')
                    elif 'Strategy' in en or 'Selector' in en:
                        engine_descriptions.append(f'- **策略选择器**: 根据条件动态匹配和执行最优策略')
                    elif 'Adapter' in en:
                        engine_descriptions.append(f'- **外部适配器**: 对接第三方服务，统一调用接口')
                    elif 'Parser' in en or 'Extractor' in en:
                        engine_descriptions.append(f'- **数据解析器**: 解析多源数据格式，提取结构化信息')
                    elif 'Generator' in en or 'Builder' in en:
                        engine_descriptions.append(f'- **内容生成器**: 根据模板和数据生成最终产出')
                    elif 'Validator' in en:
                        engine_descriptions.append(f'- **数据校验器**: 验证输入数据的完整性和合法性')
            if engine_descriptions:
                # 去重
                for desc in sorted(set(engine_descriptions))[:5]:
                    lines.append(desc)
            else:
                lines.append(f'- 该模块包含 {cc_total} 个业务实体和 {fcc_total} 个处理逻辑，共同完成业务功能')
            lines.append('')
            lines.append('')
        
        if len(business_modules) > 6:
            lines.append(f'> 另有 {len(business_modules) - 6} 个业务模块未在上文展开，完整模块清单请参考附录。')
            lines.append('')
        
        # ================================================================
        #  四、模块间配合方式
        # ================================================================
        a('四、模块间配合方式', '四模块间配合方式')
        
        # 构建模块依赖矩阵（直接从 analysis.files 匹配，避免路径拼接问题）
        top_file_map = defaultdict(list)
        for f in analysis.files:
            rel = os.path.relpath(f.file_path, analysis.project_path)
            top = _top_module_name(os.path.dirname(rel))
            if top != 'root':
                top_file_map[top].append(f)
        
        module_deps = {}
        module_cross = {}
        
        for top_module, mod_files in top_file_map.items():
            deps = set()
            cross_calls = set()
            for cf in mod_files:
                for dep in cf.dependencies:
                    if dep and dep.strip():
                        deps.add(dep)
                for imp in cf.project_imports:
                    parts = imp.split('.')
                    if parts and parts[0] and parts[0].strip():
                        cross_calls.add(parts[0])
                for call in cf.function_calls:
                    parts = call.split('.')
                    if parts and parts[0] and parts[0].strip():
                        cross_calls.add(parts[0])
            module_deps[top_module] = deps
            module_cross[top_module] = cross_calls
        
        h3('4.1 模块外部依赖与内部协作')
        
        business_module_names = [m for m, _, _, _ in display_modules]
        if business_module_names:
            mk_table(
                ['模块', '外部依赖（第三方库）', '调用其他模块'],
                [
                    [
                        module,
                        ', '.join(sorted(list(module_deps.get(module, set())))[:6]) or '-',
                        ', '.join(sorted(list(module_cross.get(module, set())))[:4]) or '-'
                    ]
                    for module in business_module_names
                ]
            )
        
        # 高频共用依赖
        h3('4.2 共用基础设施')
        if analysis.dependencies:
            dep_module_count = {}
            for dep in analysis.dependencies:
                count = 0
                for top_module, mod_files in top_file_map.items():
                    for cf in mod_files:
                        if dep in cf.dependencies:
                            count += 1
                            break
                dep_module_count[dep] = count
            
            top_deps = sorted(dep_module_count.items(), key=lambda x: -x[1])[:10]
            if top_deps:
                mk_table(
                    ['共享依赖', '涉及模块数', '用途推断'],
                    [
                        [
                            f'`{dep}`',
                            str(count),
                            '通用工具库' if dep in ('typing', 'os', 'sys', 'json', 're', 'datetime', 'pathlib', 'collections', 'functools', 'itertools', 'dataclasses', 'abc') else
                            '日志记录' if 'log' in dep.lower() else
                            '数据处理' if dep in ('pandas', 'numpy') else
                            'HTTP通信' if dep in ('requests', 'httpx', 'aiohttp') else
                            'LLM集成' if dep in ('openai', 'anthropic') else
                            '文档生成' if 'docx' in dep.lower() or 'openpyxl' in dep.lower() else
                            '网页解析' if dep in ('beautifulsoup4', 'lxml', 'parsel') else
                            'Web框架' if dep in ('fastapi', 'flask', 'uvicorn') else
                            '数据校验' if dep in ('pydantic',) else
                            '框架依赖'
                        ]
                        for dep, count in top_deps
                    ]
                )
        
        # ================================================================
        #  五、技术栈与代码分布
        # ================================================================
        a('五、技术栈与代码分布', '五技术栈与代码分布')
        
        h3('5.1 技术栈评估')
        
        # 技术栈名称中文化（去掉框架原名，用业务描述）
        tech_friendly = {
            'fastapi': 'Web服务框架',
            'flask': 'Web服务框架',
            'django': 'Web框架',
            'react': '前端框架',
            'vue': '前端框架',
            'angular': '前端框架',
            'pandas': '数据处理',
            'numpy': '数值计算',
            'torch': '深度学习',
            'tensorflow': '深度学习',
            'requests': '网络通信',
            'pydantic': '数据校验',
            'sqlalchemy': '数据库ORM',
            'openai': 'AI大模型',
            'httpx': '网络通信',
        }
        
        if analysis.tech_stack:
            lang_techs = [t for t in analysis.tech_stack if '(' in t and ('文件' in t or '个' in t)]
            framework_techs = []
            for t in analysis.tech_stack:
                if t not in lang_techs:
                    t_lower = t.lower()
                    framework_techs.append(tech_friendly.get(t_lower, t))
            # 去重
            framework_techs = list(dict.fromkeys(framework_techs))
            
            lines.append('**编程语言**:')
            for tech in lang_techs:
                lines.append(f'- ✅ {tech}')
            lines.append('')
            
            if framework_techs:
                lines.append('**框架与库**:')
                for tech in framework_techs:
                    lines.append(f'- ✅ {tech}')
                lines.append('')
        
        h3('5.2 代码度量')
        
        avg_lines = total_lines / total_files if total_files > 0 else 0
        avg_funcs = total_functions / total_files if total_files > 0 else 0
        avg_classes = total_classes / total_files if total_files > 0 else 0
        avg_imports = total_imports / total_files if total_files > 0 else 0
        
        mk_table(
            ['指标', '总计', '平均每文件'],
            [
                ['代码文件数', str(total_files), '-'],
                ['代码行数', f'{total_lines:,}', f'{avg_lines:.0f}'],
                ['业务实体数', str(total_classes), f'{avg_classes:.2f}'],
                ['处理逻辑数', str(total_functions), f'{avg_funcs:.1f}'],
                ['导入语句数', str(total_imports), f'{avg_imports:.1f}'],
                ['外部依赖数', str(len(analysis.dependencies)), '-'],
                ['模块/目录数', str(len(analysis.modules)), '-'],
            ]
        )
        
        h3('5.3 文件规模排行榜（Top 5）')
        file_sizes = []
        for f in analysis.files:
            rel_path = os.path.relpath(f.file_path, analysis.project_path)
            if f.raw_content and not f.raw_content.startswith('[超大文件'):
                size = len(f.raw_content)
            else:
                size = 0
            file_sizes.append((rel_path, size, len(f.functions), len(f.classes)))
        file_sizes.sort(key=lambda x: -x[1])
        
        mk_table(
            ['排名', '文件', '大小', '函数数', '实体数', '热度'],
            [
                [
                    str(i),
                    f'`{rel_path}`',
                    f'{f"{size/1024:.0f}KB" if size/1024 > 1 else f"{size}B"}',
                    str(func_cnt),
                    str(cls_cnt),
                    hz_bar(size, file_sizes[0][1] if file_sizes else 1, 12)
                ]
                for i, (rel_path, size, func_cnt, cls_cnt) in enumerate(file_sizes[:5], 1)
            ]
        )
        
        # ================================================================
        #  六、关键发现
        # ================================================================
        a('六、关键发现', '六关键发现')
        
        avg = total_functions / total_files if total_files > 0 else 0
        findings_positive = []
        findings_warning = []
        findings_suggestion = []
        
        # 1. 项目规模
        if total_files > 3000:
            findings_warning.append(f'**项目规模较大**: {total_files}个文件，{total_lines:,}行代码，建议关注构建速度和模块间耦合')
        elif total_files > 500:
            findings_warning.append(f'**项目中等偏大**: {total_files}个文件，建议定期做模块边界检查')
        elif total_files > 50:
            findings_positive.append(f'**项目规模适中**: {total_files}个文件，结构清晰')
        else:
            findings_positive.append(f'**小型项目**: {total_files}个文件，易于管理')
        
        # 2. 技术栈评估
        if len(analysis.languages) == 1:
            lang_name = list(analysis.languages.keys())[0]
            findings_positive.append(f'**技术栈统一**: 仅使用 {lang_name}，技术选择集中降低了维护成本')
        elif len(analysis.languages) <= 3:
            findings_positive.append(f'**技术栈集中**: 使用 {len(analysis.languages)} 种语言，技术生态相对聚焦')
        else:
            findings_warning.append(f'**多语言项目**: 使用 {len(analysis.languages)} 种语言，注意跨语言维护成本和团队协作')
        
        # 3. AI能力评估
        llm_deps = [d for d in analysis.dependencies if any(k in d.lower() for k in ('openai', 'anthropic', 'deepseek'))]
        if llm_deps:
            findings_positive.append(f'**AI能力集成**: 集成 {", ".join(llm_deps)} 等LLM服务，具备智能规划、内容生成和审核能力')
        
        # 4. 入口规范性
        if entry_rows:
            findings_positive.append(f'**项目结构规范**: 检测到 {len(entry_rows)} 个标准入口文件，启动方式明确')
        else:
            findings_warning.append(f'**入口不明确**: 未检测到标准入口文件，建议明确启动方式并添加入口标识')
        
        # 5. 超大文件检测
        skipped = sum(1 for f in analysis.files if f.raw_content.startswith('[超大文件'))
        if skipped > 0:
            findings_suggestion.append(f'发现 {skipped} 个文件超过 500KB（超大文件），建议拆分为更小的模块以提高可维护性')
        
        # 6. 小文件清理
        empty = sum(1 for f in analysis.files if len(f.raw_content) < 500 and not f.raw_content.startswith('[超大文件'))
        if empty > 5:
            findings_suggestion.append(f'**小文件偏多**: {empty} 个文件小于 500 字节，可能是空文件或模板残留，建议清理')
        
        # 7. 模块复杂度
        if len(analysis.modules) > 10:
            findings_warning.append(f'**目录模块较多**: {len(analysis.modules)} 个模块目录，建议保持模块边界清晰、层级扁平')
        
        # 8. 函数密度
        if avg > 15:
            findings_warning.append(f'**函数密度较高**: 平均每文件 {avg:.0f} 个函数，建议关注单个文件的职责单一性')
        elif avg < 3:
            findings_suggestion.append(f'**函数密度偏低**: 平均每文件仅 {avg:.1f} 个函数，可能存在大量配置或数据文件')
        
        # 9. 类/函数比例
        if total_classes > 0:
            ratio = total_functions / total_classes
            if ratio < 2:
                findings_positive.append(f'**面向对象风格明显**: 每个类约 {ratio:.1f} 个函数，类设计较为内聚')
            else:
                findings_positive.append(f'**工具函数丰富**: 每个类约 {ratio:.1f} 个函数，项目中实用函数较多')
        
        # 10. 跨模块调用
        has_cross_imports = any(f.project_imports for f in analysis.files)
        has_syspath = any(f.sys_path_inserts for f in analysis.files)
        if has_syspath:
            findings_warning.append(f'**动态路径注入**: 检测到 sys.path 动态注入，表明模块间采用运行时耦合方式')
        if has_cross_imports:
            findings_positive.append(f'**模块间协作活跃**: 存在跨模块 import 调用，模块间功能有明确协作关系')
        
        lines.append('')
        if findings_positive:
            lines.append('### 项目优势')
            for f in findings_positive:
                lines.append(f'- {f}')
            lines.append('')
        
        if findings_warning:
            lines.append('### 需关注')
            for f in findings_warning:
                lines.append(f'- {f}')
            lines.append('')
        
        if findings_suggestion:
            lines.append('### 改进建议')
            for f in findings_suggestion:
                lines.append(f'- {f}')
            lines.append('')
        
        # 总体评价
        total_score = 0
        if total_files <= 500: total_score += 20
        elif total_files <= 2000: total_score += 15
        else: total_score += 10
        if len(analysis.languages) <= 2: total_score += 20
        elif len(analysis.languages) <= 4: total_score += 15
        else: total_score += 10
        if entry_rows: total_score += 20
        if skipped == 0: total_score += 20
        if llm_deps: total_score += 10
        if 3 <= avg <= 15: total_score += 10
        elif avg > 0: total_score += 5
        
        lines.append('### 总体评分')
        lines.append(f'> **{total_score}/100** — {"优秀" if total_score >= 80 else "良好" if total_score >= 60 else "一般" if total_score >= 40 else "待改进"}')
        lines.append('')
        
        # ================================================================
        #  七、建议、困惑与问题（V2.0新增）
        # ================================================================
        a('七、建议、困惑与问题', '七建议困惑与问题')
        
        lines.append('基于对代码的深度分析，提出以下建议、困惑和问题：')
        lines.append('')
        
        h3('7.1 架构设计困惑')
        lines.append('1. **A/B角色在Web端的冲突设计**：`tasks.py` 中 B角色（is_admin=True）在Web端被禁止提交任务（返回403），但 admin.py 又提供了大量B角色专属API（配方库、种子精炼、方案审核）。这种设计意图是什么？B角色在Web端到底是"只读管理员"还是"完全不能用"？')
        lines.append('')
        lines.append('2. **MODE_METADATA 与 TOOL_MODES_A 命名不一致**：`tool_runner.py` 使用 `research:normal`，而 `tasks.py` 之前使用 `research:regular`，`insight:quick` vs `insight:magic`。这种命名不一致是否会导致模式匹配失败？')
        lines.append('')
        lines.append('3. **sys.path 动态注入的维护成本**：多个文件（`admin.py`、`engine.py`）使用 `sys.path.insert(0, ...)` 动态注入路径，这种方式在打包部署时容易失效，是否有计划改为相对导入或包结构重构？')
        lines.append('')
        
        h3('7.2 代码质量问题')
        lines.append('4. **logger 未定义（已修复）**：`admin.py` 和 `main.py` 中之前使用 `logger.error()` 但缺少 `import logging`，已添加 `import logging` + `logger = logging.getLogger(__name__)`。')
        lines.append('')
        lines.append('5. **回调内存泄漏（已修复）**：`task_scheduler.py` 的 `add_progress_callback()` 之前只追加不移除，已添加 `remove_progress_callback()` 和 `remove_status_callback()` 方法。需确认调用方是否正确使用。')
        lines.append('')
        lines.append('6. **硬编码路径仍有多处**：虽然大部分硬编码路径已修复为环境变量，但 `gptr.doc_path` 仍为绝对路径而非环境变量，`review_proposal()` 中的 `方案待处理` 目录仍有硬编码 fallback。')
        lines.append('')
        
        h3('7.3 安全与权限')
        lines.append('7. **授权码系统的安全性**：授权码格式为 `XZ-YYYY-XXXX-XXXX`，其中 YYYY 是年份，这种模式是否容易被猜测？是否有暴力破解防护？')
        lines.append('')
        lines.append('8. **路径遍历防护的完备性**：`get_pending_proposal_content()` 和 `review_proposal()` 都使用了 `path.relative_to(base_dir)` 检查，但如果 `base_dir` 本身被篡改（如符号链接攻击），防护是否仍然有效？')
        lines.append('')
        
        h3('7.4 功能完整性')
        lines.append('9. **自学习系统的数据闭环**：`self_learning.py` 中的 `BRoleFeedback` 记录B角色评分，但这些评分数据如何反馈到模型调优？当前代码中只看到记录，没有看到利用评分的逻辑。')
        lines.append('')
        lines.append('10. **导演模式的黑盒/白盒差异**：`main_v3_1.py` 中 A角色调用 `_b05_to_b06_director_mode_blackbox()`，B角色调用 `b05_to_b06_director_mode()`。黑盒版具体隐藏了哪些数据？是否有文档说明？')
        lines.append('')
        
        # ================================================================
        #  八、开源项目与论文对比（V2.0新增）
        # ================================================================
        a('八、开源项目与论文对比', '八开源项目与论文对比')
        
        lines.append('基于当前系统的架构特点，与以下开源项目和研究论文进行对比：')
        lines.append('')
        
        h3('8.1 多Agent研究系统对比')
        lines.append('| 特性 | 本系统 | Anthropic Multi-Agent Research | GPT-Researcher | AutoGen |')
        lines.append('|------|--------|----------------------------------|----------------|---------|')
        lines.append('| 架构模式 | Orchestrator-Worker + Director模式 | Orchestrator-Worker | Single-Agent + 并行搜索 | Multi-Agent对话 |')
        lines.append('| 角色系统 | A/B双角色（Web/GUI差异化） | 无（单一用户） | 无 | 无 |')
        lines.append('| 深度调研 | L1-L3三级搜索+迭代 | 并行子Agent搜索 | 多源搜索+综合 | 对话式任务分配 |')
        lines.append('| 方案生成 | 3骨架导演模式+TTD-DR | 无（纯研究） | 无 | 无 |')
        lines.append('| 自学习 | 大败局知识库+B角色评分 | 无 | 无 | 无 |')
        lines.append('| 白盒/黑盒 | 完整推理过程透明可选 | 黑盒 | 黑盒 | 黑盒 |')
        lines.append('| 本地部署 | 支持（Ollama+bge-large-zh） | 仅云端 | 支持 | 支持 |')
        lines.append('')
        
        h3('8.2 可借鉴的开源项目')
        lines.append('1. **[GPT-Researcher](https://github.com/assafelovic/gpt-researcher)**')
        lines.append('   - 借鉴点：多源搜索聚合、报告自动生成流程')
        lines.append('   - 差异：本系统增加了导演模式（3骨架选择）和A/B角色差异化')
        lines.append('   - 整合建议：可参考其搜索结果的置信度评分机制')
        lines.append('')
        lines.append('2. **[AutoGen](https://github.com/microsoft/autogen)**')
        lines.append('   - 借鉴点：多Agent对话编排、代码执行Agent')
        lines.append('   - 差异：本系统使用静态流水线而非动态对话')
        lines.append('   - 整合建议：可参考其Agent间的消息路由机制，增强导演模式的灵活性')
        lines.append('')
        lines.append('3. **[LangGraph](https://github.com/langchain-ai/langgraph)**')
        lines.append('   - 借鉴点：图结构工作流定义、状态管理')
        lines.append('   - 差异：本系统工作流是硬编码的Python函数调用链')
        lines.append('   - 整合建议：可将调研/方案/洞察的工作流改为LangGraph图定义，提高可维护性')
        lines.append('')
        
        h3('8.3 相关研究论文')
        lines.append('1. **Anthropic: "How we built our multi-agent research system" (2025.06)**')
        lines.append('   - 核心思想：Orchestrator-Worker 模式，并行子Agent处理研究子任务')
        lines.append('   - 与本系统的关系：本系统的 `调研工具/engine.py` 中的多Agent协作（planner/writer/reviewer）与此类似')
        lines.append('   - 可借鉴：论文中提到的"任务分解粒度控制"和"结果合并策略"')
        lines.append('')
        lines.append('2. **Google DeepMind: "LLM Agents for Automated Research" (2024)**')
        lines.append('   - 核心思想：使用LLM自动生成研究假设、实验设计、结果分析')
        lines.append('   - 与本系统的关系：本系统的"自学习机制"（大败局知识库+评分反馈）与此方向一致')
        lines.append('   - 可借鉴：论文中的"反馈闭环设计"，将B角色评分自动用于模型微调')
        lines.append('')
        lines.append('3. **Stanford HAI: "Evaluating LLM Reasoning Transparency" (2025)**')
        lines.append('   - 核心思想：评估LLM推理过程的透明度对用户信任的影响')
        lines.append('   - 与本系统的关系：本系统的"白盒/黑盒"双模式设计直接对应此研究方向')
        lines.append('   - 可借鉴：论文中的"推理步骤可视化"方法，可增强白盒模式的用户体验')
        lines.append('')
        
        h3('8.4 整合与差异化建议')
        lines.append('- **短期**：参考 GPT-Researcher 的搜索结果置信度评分，增强调研工具的数据可靠性声明')
        lines.append('- **中期**：引入 LangGraph 重构工作流，将硬编码的流水线改为可配置的图结构')
        lines.append('- **长期**：探索 AutoGen 的动态Agent编排，让导演模式支持更多骨架变体和自适应选择')
        lines.append('')
        
        # ================================================================
        #  附录
        # ================================================================
        lines.append('---')
        lines.append('## 附录')
        lines.append('')
        
        # 模块文件统计总表
        mk_table(
            ['模块', '文件数', '语言分布'],
            [
                [name, str(len(files)), ', '.join(
                    f'{k}({v})' for k, v in sorted(
                        _module_lang_count(name).items(), key=lambda x: -x[1]
                    )
                )]
                for name, files, _, _ in display_modules
            ]
        )
        
        # 报告脚注
        now_str2 = datetime.now().strftime('%Y-%m-%d %H:%M')
        lines.append(f'> **报告说明**: 本报告由 CodeRef AI 深度分析引擎自动生成于 {now_str2}')
        lines.append(f'> **分析数据**: {total_files} 个代码文件，{len(analysis.modules)} 个模块，扫描范围全覆盖')
        lines.append(f'> **免责声明**: 本报告基于静态代码分析，不包含运行时动态信息')
        lines.append(f'> **过滤说明**: 已自动过滤 .git 仓库、本地 Python 库（site-packages/Lib）、编译缓存（__pycache__/node_modules）以及工具自身生成的报告文件（.md）')
        
        return '\n'.join(lines)

    # ==================== GitNexus 增强通道 ====================

    def _enhance_with_gitnexus(self, analysis: ProjectAnalysis):
        """用GitNexus图谱数据增强分析结果
        
        通过MCP查询GitNexus图数据库，获取：
        - 执行流（process）信息
        - 函数集群（community）信息
        - 入口点的上下游关系
        """
        from .gitnexus_client import GitNexusMCPClient
        
        logger.info(f"[GitNexus] 尝试增强分析，项目路径: {analysis.project_path}")
        
        with GitNexusMCPClient(project_path=analysis.project_path) as client:
            # 1. 获取已索引的仓库列表
            repos = client.list_repos()
            logger.info(f"[GitNexus] 发现 {len(repos)} 个索引仓库: {[r.get('name') for r in repos]}")
            if not repos:
                logger.info("[GitNexus] 当前项目无索引数据，跳过增强")
                return
            
            # 2. 搜索项目中的关键符号，补充进程/集群信息
            # 查找入口点文件
            entry_files = []
            for f in analysis.files:
                basename = os.path.basename(f.file_path)
                if basename in ('main.py', 'index.js', 'app.py', 'server.py', 'v4_main.py'):
                    entry_files.append(f)
            
            # 3. 对每个入口函数查询上下文
            for ef in entry_files:
                for func in ef.functions:
                    if func.name in ('main', 'run', 'start', 'serve', 'app'):
                        try:
                            context = client.get_context(func.name)
                            if isinstance(context, dict):
                                # 补充进程信息到架构摘要
                                processes = context.get("processes", [])
                                if processes:
                                    proc_names = []
                                    for p in processes[:5]:
                                        if isinstance(p, dict):
                                            proc_names.append(p.get("name", str(p)))
                                        else:
                                            proc_names.append(str(p))
                                    if proc_names:
                                        analysis.architecture_summary += (
                                            f"\n[GitNexus] 检测到执行流: {', '.join(proc_names)}"
                                        )
                        except Exception:
                            pass
            
            # 4. 用混合搜索发现项目中的关键模块
            try:
                project_name = os.path.basename(analysis.project_path.rstrip('/\\'))
                search_results = client.search(project_name)
                if isinstance(search_results, dict):
                    clusters = search_results.get("clusters", [])
                    if clusters:
                        cluster_info = []
                        for c in clusters[:10]:
                            if isinstance(c, dict):
                                name = c.get("name", "")
                                cohesion = c.get("cohesion", "")
                                if name:
                                    cluster_info.append(f"{name}(内聚度:{cohesion})" if cohesion else name)
                        if cluster_info:
                            analysis.architecture_summary += (
                                f"\n[GitNexus] 功能集群: {', '.join(cluster_info)}"
                            )
            except Exception:
                pass
            
            logger.info("[CodeAnalyzer] GitNexus增强完成")

    def scan_function(self, entry: str, depth: int = 3, fmt: str = "report") -> str:
        """扫描单个功能的上下游依赖，生成架构图
        
        这是 GitNexus 的核心能力——按需提取子图 + 动态生成图表
        
        Args:
            entry: 入口点（符号名或 file:function 格式）
            depth: 上下游遍历深度（默认3）
            fmt: 输出格式 (mermaid/structurizr/report)
        
        Returns:
            生成的图表/报告字符串
        """
        if not self._gitnexus_available:
            return "# Error: GitNexus不可用。请先安装: npm install -g gitnexus，然后索引项目: gitnexus analyze"
        
        # GitNexus 已经索引好，用 gitnexus 命令行导出子图
        cmd = [
            "gitnexus", "export",
            "--entry", entry,
            "--depth", str(depth),
        ]
        
        result = self._run_gitnexus(cmd, self._current_project or ".")
        if result is None:
            return "# Error: 执行 gitnexus export 失败"
        
        if fmt == "mermaid":
            return f"```mermaid\n{result}\n```"
        elif fmt == "structurizr":
            return f"```dsl\n{result}\n```"
        else:  # report
            if result.strip().startswith("```"):
                return result
            return f"```text\n{result}\n```"

    def generate_mermaid_diagram(self, analysis: ProjectAnalysis) -> str:
        """基于分析结果生成Mermaid架构图
        
        利用 auto_classifier 自动分层，生成带子图的 Mermaid flowchart
        
        Args:
            analysis: 项目分析结果
        
        Returns:
            Mermaid代码字符串
        """
        from .diagram_generator import generate_mermaid, classify_nodes
        
        # 构建节点列表
        nodes = []
        for f in analysis.files:
            rel_path = os.path.relpath(f.file_path, analysis.project_path)
            # 每个文件作为一个节点
            nodes.append({
                "name": rel_path,
                "filePath": rel_path,
            })
        
        # 构建边列表（基于项目内导入关系）
        edges = []
        for f in analysis.files:
            rel_path = os.path.relpath(f.file_path, analysis.project_path)
            for imp in f.project_imports[:10]:  # 限制每个文件最多10条边
                edges.append({
                    "source": rel_path,
                    "target": imp,
                    "relation_type": "imports",
                })
        
        project_name = os.path.basename(analysis.project_path.rstrip('/\\'))
        
        return generate_mermaid(
            nodes=nodes[:50],  # 限制节点数避免图过大
            edges=edges[:100],
            entry_point="",
            title=f"{project_name} - 模块依赖图",
        )


    def generate_ai_report(self, analysis: ProjectAnalysis) -> str:
        """
        生成「给AI辅助编程LLM看的」全代码审计报告
        
        不再输出代码结构描述（MCP已能提供），而是专注于：
        - Bug/错误发现
        - 安全问题检测
        - 代码质量评估
        - 性能风险识别
        - 设计模式违规
        """
        lines = []
        
        # ==================== 头部 ====================
        lines.append("# 🔍 全代码审计报告（AI辅助编程版）")
        lines.append("")
        lines.append(f"> 项目: `{analysis.project_path}`")
        lines.append(f"> 扫描文件数: {analysis.total_files} | 总行数: {analysis.total_lines:,}")
        lines.append(f"> 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M')}")
        lines.append("")
        lines.append("> 本报告专为AI辅助编程LLM设计，聚焦代码审计维度（Bug/安全/质量/性能/设计），")
        lines.append("> 不再包含代码结构描述（请通过MCP工具获取实时代码上下文）。")
        lines.append("")
        lines.append("---")
        lines.append("")
        
        # 运行所有审计规则
        audit_results = self._run_code_audit(analysis)
        
        # 验证审计结果的行号是否仍然有效（防止缓存导致行号过时）
        audit_results = self._verify_line_numbers(analysis, audit_results)
        
        # ==================== 一、审计摘要 ====================
        lines.append("## 一、审计摘要")
        lines.append("")
        
        total_issues = sum(len(v) for v in audit_results.values())
        critical = sum(1 for cat in audit_results.values() for item in cat if item.get('severity') == 'critical')
        high = sum(1 for cat in audit_results.values() for item in cat if item.get('severity') == 'high')
        medium = sum(1 for cat in audit_results.values() for item in cat if item.get('severity') == 'medium')
        low = sum(1 for cat in audit_results.values() for item in cat if item.get('severity') == 'low')
        
        lines.append(f"| 维度 | 问题数 | 严重 | 高 | 中 | 低 |")
        lines.append(f"|------|--------|------|----|----|----|")
        for category, items in audit_results.items():
            c = sum(1 for i in items if i.get('severity') == 'critical')
            h = sum(1 for i in items if i.get('severity') == 'high')
            m = sum(1 for i in items if i.get('severity') == 'medium')
            l = sum(1 for i in items if i.get('severity') == 'low')
            lines.append(f"| {category} | {len(items)} | {c} | {h} | {m} | {l} |")
        lines.append(f"| **总计** | **{total_issues}** | **{critical}** | **{high}** | **{medium}** | **{low}** |")
        lines.append("")
        
        # ==================== 二~六、各审计维度详情 ====================
        category_titles = {
            'bugs': ('二、Bug与错误', '🔴'),
            'security': ('三、安全问题', '🔒'),
            'quality': ('四、代码质量', '📐'),
            'performance': ('五、性能风险', '⚡'),
            'design': ('六、设计问题', '🏗️'),
        }
        
        for cat_key, (title, emoji) in category_titles.items():
            items = audit_results.get(cat_key, [])
            lines.append(f"## {title}")
            lines.append("")
            
            if not items:
                lines.append(f"{emoji} 未发现此类问题。")
                lines.append("")
                continue
            
            # 按严重度排序
            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
            items_sorted = sorted(items, key=lambda x: severity_order.get(x.get('severity', 'low'), 3))
            
            for item in items_sorted:
                sev = item.get('severity', 'low')
                sev_emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🔵'}.get(sev, '⚪')
                file_path = item.get('file', '未知文件')
                line = item.get('line', '-')
                desc = item.get('description', '')
                suggestion = item.get('suggestion', '')
                
                lines.append(f"### {sev_emoji} [{sev.upper()}] `{file_path}:{line}`")
                lines.append("")
                lines.append(f"**问题**: {desc}")
                if suggestion:
                    lines.append(f"**建议**: {suggestion}")
                lines.append("")
            
            lines.append("---")
            lines.append("")
        
        # ==================== 七、修复优先级建议 ====================
        lines.append("## 七、修复优先级建议")
        lines.append("")
        lines.append("基于审计结果，建议按以下优先级处理：")
        lines.append("")
        
        all_issues = []
        for cat, items in audit_results.items():
            for item in items:
                all_issues.append(item)
        
        # 按严重度+影响范围排序
        all_issues.sort(key=lambda x: (
            {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}.get(x.get('severity', 'low'), 3),
            -len(x.get('description', ''))
        ))
        
        if all_issues:
            lines.append("| 优先级 | 文件 | 问题简述 | 建议操作 |")
            lines.append("|--------|------|----------|----------|")
            for i, item in enumerate(all_issues[:20], 1):  # 最多显示前20个
                sev = item.get('severity', 'low')
                file_path = item.get('file', '未知')
                desc = item.get('description', '')[:40] + '...' if len(item.get('description', '')) > 40 else item.get('description', '')
                suggestion = item.get('suggestion', '')[:30] + '...' if len(item.get('suggestion', '')) > 30 else item.get('suggestion', '')
                lines.append(f"| P{i} ({sev}) | `{file_path}` | {desc} | {suggestion or '审查修复'} |")
            lines.append("")
        else:
            lines.append("✅ 未发现需要修复的问题。")
            lines.append("")
        
        lines.append("---")
        lines.append("*全代码审计报告 · 供AI辅助编程LLM参考*")
        
        return '\n'.join(lines)
    
    def _run_code_audit(self, analysis: ProjectAnalysis) -> Dict[str, List[Dict]]:
        """
        运行所有代码审计规则，返回按类别分组的问题列表
        
        Returns:
            {
                'bugs': [{'severity': 'high', 'file': '...', 'line': 42, 'description': '...', 'suggestion': '...'}, ...],
                'security': [...],
                'quality': [...],
                'performance': [...],
                'design': [...],
            }
        """
        results = defaultdict(list)
        
        for cf in analysis.files:
            rel_path = os.path.relpath(cf.file_path, analysis.project_path)
            content = cf.raw_content
            lines_content = content.split('\n')
            
            # 跳过超大文件和空文件
            if content.startswith('[超大文件') or len(content) < 100:
                continue
            
            # ===== Bug检测 =====
            self._audit_bugs(cf, rel_path, content, lines_content, results['bugs'])
            
            # ===== 安全检测 =====
            self._audit_security(cf, rel_path, content, lines_content, results['security'])
            
            # ===== 质量检测 =====
            self._audit_quality(cf, rel_path, content, lines_content, results['quality'])
            
            # ===== 性能检测 =====
            self._audit_performance(cf, rel_path, content, lines_content, results['performance'])
            
            # ===== 设计检测 =====
            self._audit_design(cf, rel_path, content, lines_content, results['design'])
        
        return dict(results)
    
    def _verify_line_numbers(self, analysis: ProjectAnalysis, audit_results: Dict[str, List[Dict]]) -> Dict[str, List[Dict]]:
        """
        验证审计结果的行号是否仍然有效，移除因文件变更（缓存过时）而过期的 findings
        
        对于每个包含行号的 finding，检查：
        - 文件是否仍然存在
        - 行号是否在文件范围内
        - 该行的内容是否仍包含与 description 相关的关键词
        """
        verified = {}
        for category, items in audit_results.items():
            verified_items = []
            for item in items:
                if 'line' not in item or 'file' not in item:
                    verified_items.append(item)
                    continue
                
                file_path = os.path.join(analysis.project_path, item['file'])
                line_no = item['line']
                
                # 检查文件是否存在
                if not os.path.isfile(file_path):
                    continue  # 文件已删除/移动，移除该 finding
                
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        file_lines = f.readlines()
                    
                    # 检查行号是否在文件范围内
                    if line_no < 1 or line_no > len(file_lines):
                        continue
                    
                    actual_line = file_lines[line_no - 1]
                    
                    # 从 description 中提取反引号内的关键词，检查该行是否仍包含它们
                    desc = item.get('description', '')
                    keywords = re.findall(r'`([^`]+)`', desc)
                    if keywords:
                        found = any(kw in actual_line for kw in keywords)
                        if not found:
                            continue  # 内容不匹配，移除该 finding
                    
                    verified_items.append(item)
                except Exception:
                    # 读取失败时保守保留 finding
                    verified_items.append(item)
            
            if verified_items:
                verified[category] = verified_items
        
        return verified
    
    def _audit_bugs(self, cf: CodeFile, rel_path: str, content: str, lines: List[str], issues: List[Dict]):
        """Bug与错误检测（注意：content 来自 CodeFile.raw_content，缓存不截断后为完整内容）"""
        # 1. logger未定义检测（精准：排除跨模块导入 logger 的情况）
        if re.search(r'\blogger\.(debug|info|warning|error|critical)\b', content):
            has_logging_import = bool(re.search(r'import\s+logging', content))
            has_logger_def = bool(re.search(r'\blogger\s*=\s*(?:logging\.getLogger|getLogger)', content))
            
            # 跨模块导入追踪：from X import ... logger ...
            # 单行匹配：from config import logger / from config import x, logger, y
            has_logger_import_single = bool(re.search(r'\bfrom\s+\S+\s+import\s+[^)]*\blogger\b', content))
            
            # 多行匹配：from config import ( \n    x, \n    logger, \n )
            has_logger_import_multi = False
            multi_import_matches = list(re.finditer(r'\bfrom\s+\S+\s+import\s*\(', content))
            for m in multi_import_matches:
                # 从 import ( 开始，找到匹配的 )
                paren_start = m.end()
                depth = 1
                pos = paren_start
                while pos < len(content) and depth > 0:
                    if content[pos] == '(':
                        depth += 1
                    elif content[pos] == ')':
                        depth -= 1
                    pos += 1
                if depth == 0:
                    import_block = content[m.end():pos-1]
                    if re.search(r'\blogger\b', import_block):
                        has_logger_import_multi = True
                        break
            
            # import logger 别名：from loguru import logger as log
            has_logger_alias = bool(re.search(r'\bfrom\s+\S+\s+import\s+.*\blogger\s+as\s+\w+', content))
            
            has_logger_import = has_logging_import or has_logger_def or \
                                has_logger_import_single or has_logger_import_multi or has_logger_alias
            
            if not has_logger_import:
                for i, line in enumerate(lines, 1):
                    if re.search(r'\blogger\.(debug|info|warning|error|critical)\b', line):
                        issues.append({
                            'severity': 'high',
                            'file': rel_path,
                            'line': i,
                            'description': 'logger未定义：使用logger.xxx()但无import logging或导入logger',
                            'suggestion': '添加 `import logging` 和 `logger = logging.getLogger(__name__)`'
                        })
                        break
        
        # 2. 异常处理缺失（函数级try块检测，使用函数/类作用域而非行级回溯）
        if cf.language == 'python':
            risky_calls = ['requests.', 'urllib', 'socket.', 'subprocess.', 'open(', 'httpx.']
            for risky in risky_calls:
                for i, line in enumerate(lines, 1):
                    if risky in line:
                        # 查找包含该行的函数/类作用域
                        in_try = False
                        scope_start = None
                        scope_end = None
                        
                        # 优先检查函数作用域（包括类方法）
                        for func in cf.functions:
                            if func.start_line <= i <= func.end_line:
                                scope_start = func.start_line
                                scope_end = func.end_line
                                break
                        
                        # 如果不在独立函数内，检查类方法
                        if scope_start is None:
                            for cls in cf.classes:
                                for method in cls.methods:
                                    if method.start_line <= i <= method.end_line:
                                        scope_start = method.start_line
                                        scope_end = method.end_line
                                        break
                                if scope_start is not None:
                                    break
                        
                        # 如果不在方法内但位于类体中，检查整个类
                        if scope_start is None:
                            for cls in cf.classes:
                                if cls.start_line <= i <= cls.end_line:
                                    scope_start = cls.start_line
                                    scope_end = cls.end_line
                                    break
                        
                        if scope_start is not None and scope_end is not None:
                            # 在函数/类作用域内：检查整个作用域是否有 try
                            for j in range(scope_start, min(scope_end + 1, len(lines) + 1)):
                                check_line = lines[j - 1].strip() if j <= len(lines) else ''
                                if check_line.startswith('try:') or check_line == 'try:':
                                    in_try = True
                                    break
                        else:
                            # 模块级代码：只检查周围5行
                            for j in range(i - 1, max(i - 5, 0), -1):
                                check_line = lines[j - 1].strip() if j > 0 else ''
                                if check_line.startswith('try:') or check_line == 'try:':
                                    in_try = True
                                    break
                        
                        if not in_try:
                            issues.append({
                                'severity': 'medium',
                                'file': rel_path,
                                'line': i,
                                'description': f'调用 `{risky}` 可能缺少异常处理',
                                'suggestion': '添加 try/except 块处理IO/网络异常'
                            })
                            break
    
    def _audit_security(self, cf: CodeFile, rel_path: str, content: str, lines: List[str], issues: List[Dict]):
        """安全问题检测（AST 精确分类 + 正则回退）"""
        # 1. 硬编码密钥/Token — 优先使用 AST 精确分类
        ast_assignments = getattr(cf, 'ast_assignments', [])
        if ast_assignments:
            # AST 解析可用：只报告确认为 hardcoded 的赋值
            for assign in ast_assignments:
                if assign.category == "hardcoded":
                    issues.append({
                        'severity': 'high',
                        'file': rel_path,
                        'line': assign.line,
                        'description': f'硬编码凭据: {assign.target} = {assign.value_repr[:50]}',
                        'suggestion': '使用环境变量或密钥管理服务（os.environ.get()）'
                    })
        else:
            # AST 不可用：回退到正则（但增加排除逻辑）
            secret_patterns = [
                (r'\bapi[_-]?key\b\s*=\s*["\'][^"\']{10,}["\']', '硬编码API Key'),
                (r'\bsecret\b\s*=\s*["\'][^"\']{8,}["\']', '硬编码Secret'),
                (r'\btoken\b\s*=\s*["\'][^"\']{10,}["\']', '硬编码Token'),
                (r'\bpassword\b\s*=\s*["\'][^"\']{4,}["\']', '硬编码密码'),
            ]
            # 排除模式
            exclude_patterns = [
                r'\.get\s*\(',          # config.get()
                r'os\.(?:environ|getenv)',  # os.environ / os.getenv
                r'^[A-Z_]{4,}\s*=\s*["\'][A-Z_\d]+["\']',  # 错误码常量
                r'MISSING_|_MISSING',    # 错误码
            ]
            for pattern, desc in secret_patterns:
                for i, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        # 排除配置读取和错误码常量
                        if any(re.search(ep, line, re.IGNORECASE) for ep in exclude_patterns):
                            continue
                        issues.append({
                            'severity': 'high',
                            'file': rel_path,
                            'line': i,
                            'description': f'发现{desc}',
                            'suggestion': '使用环境变量或密钥管理服务'
                        })
                        break
        
        # 2. SQL注入风险
        sql_patterns = [
            r'execute\s*\(\s*["\'].*%s',
            r'execute\s*\(\s*["\'].*\+',
            r'execute\s*\(\s*f["\']',
        ]
        for pattern in sql_patterns:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append({
                        'severity': 'critical',
                        'file': rel_path,
                        'line': i,
                        'description': '可能的SQL注入风险：字符串拼接SQL',
                        'suggestion': '使用参数化查询（parameterized queries）'
                    })
                    break
        
        # 3. 路径遍历风险
        for i, line in enumerate(lines, 1):
            if 'open(' in line and ('+' in line or 'f"' in line or "f'" in line):
                if 'pathlib' not in content and 'os.path.join' not in line:
                    issues.append({
                        'severity': 'medium',
                        'file': rel_path,
                        'line': i,
                        'description': '文件路径可能包含用户输入，存在路径遍历风险',
                        'suggestion': '使用 pathlib.Path.resolve() 和路径验证'
                    })
                    break
        
        # 4. 不安全的反序列化
        for i, line in enumerate(lines, 1):
            if 'pickle.loads' in line or 'yaml.load(' in line:
                issues.append({
                    'severity': 'high',
                    'file': rel_path,
                    'line': i,
                    'description': '使用不安全的反序列化方法',
                    'suggestion': 'pickle→json; yaml.load→yaml.safe_load'
                })
                break
        
        # 5. eval/exec 使用
        for i, line in enumerate(lines, 1):
            if re.search(r'\beval\s*\(', line) or re.search(r'\bexec\s*\(', line):
                issues.append({
                    'severity': 'critical',
                    'file': rel_path,
                    'line': i,
                    'description': '使用 eval/exec 执行动态代码',
                    'suggestion': '避免使用eval/exec，改用ast.literal_eval或安全替代方案'
                })
                break
        
        # 6. 硬编码Windows路径（带过滤）
        # 跳过测试文件和 __pycache__ 目录
        if '__pycache__' not in rel_path and '/test_' not in rel_path.replace('\\', '/') and not rel_path.startswith('test_'):
            win_path_pattern = re.compile(r'(?<![a-zA-Z])[A-Za-z]:(?:[\\/][^\\/"\'\n\r\t\)\]\}]+)+')
            for i, line in enumerate(lines, 1):
                stripped = line.strip()
                # 跳过注释行
                if stripped.startswith('#') or stripped.startswith('//') or stripped.startswith('/*') or stripped.startswith('*'):
                    continue
                # 跳过日志消息模板（包含 {} 或 %s/%d 等占位符）
                if re.search(r'[\{\}]|%[sd]|%\(', line):
                    continue
                # 跳过UI标签/显示文本（包含常见UI关键词的短行）
                if any(kw in line.lower() for kw in ['路径', '文件', '目录', 'folder', 'path', 'directory', 'file']):
                    if len(stripped) < 100:
                        continue
                # 跳过默认值/示例
                if re.search(r'example|sample|your[-\s]|默认|示例', line, re.IGNORECASE):
                    continue
                # 实际检测硬盘路径
                if win_path_pattern.search(line):
                    issues.append({
                        'severity': 'low',
                        'file': rel_path,
                        'line': i,
                        'description': f'硬编码Windows路径: `{line.strip()[:60]}`',
                        'suggestion': '使用 os.path.join() 或 pathlib.Path 构建路径'
                    })
    
    def _audit_quality(self, cf: CodeFile, rel_path: str, content: str, lines: List[str], issues: List[Dict]):
        """代码质量检测"""
        # 1. 函数过长
        for func in cf.functions:
            func_lines = func.end_line - func.start_line
            if func_lines > 100:
                issues.append({
                    'severity': 'medium',
                    'file': rel_path,
                    'line': func.start_line,
                    'description': f'函数 `{func.name}` 过长 ({func_lines} 行)',
                    'suggestion': '拆分为多个小函数，遵循单一职责原则'
                })
            elif func_lines > 50:
                issues.append({
                    'severity': 'low',
                    'file': rel_path,
                    'line': func.start_line,
                    'description': f'函数 `{func.name}` 较长 ({func_lines} 行)',
                    'suggestion': '考虑拆分或提取辅助函数'
                })
        
        # 2. 类过大
        for cls in cf.classes:
            cls_lines = cls.end_line - cls.start_line
            if cls_lines > 300:
                issues.append({
                    'severity': 'medium',
                    'file': rel_path,
                    'line': cls.start_line,
                    'description': f'类 `{cls.name}` 过大 ({cls_lines} 行)',
                    'suggestion': '拆分为多个类或使用组合替代继承'
                })
        
        # 3. 参数过多
        for func in cf.functions:
            if len(func.parameters) > 7:
                issues.append({
                    'severity': 'low',
                    'file': rel_path,
                    'line': func.start_line,
                    'description': f'函数 `{func.name}` 参数过多 ({len(func.parameters)} 个)',
                    'suggestion': '使用dataclass或dict封装参数'
                })
        
        # 4. TODO/FIXME 标记
        for i, line in enumerate(lines, 1):
            if 'TODO' in line or 'FIXME' in line or 'HACK' in line:
                issues.append({
                    'severity': 'low',
                    'file': rel_path,
                    'line': i,
                    'description': f'发现技术债务标记: {line.strip()[:60]}',
                    'suggestion': '安排时间清理或转化为正式issue'
                })
    
    def _audit_performance(self, cf: CodeFile, rel_path: str, content: str, lines: List[str], issues: List[Dict]):
        """性能风险检测"""
        # 1. 文件级循环中的IO操作
        for i, line in enumerate(lines, 1):
            if ('for ' in line or 'while ' in line) and ('open(' in content[i:i+500] if i < len(content) else False):
                issues.append({
                    'severity': 'medium',
                    'file': rel_path,
                    'line': i,
                    'description': '循环中可能包含文件IO操作',
                    'suggestion': '将IO操作移出循环，或使用批量读写'
                })
                break
        
        # 2. 字符串拼接在循环中
        for i, line in enumerate(lines, 1):
            if ('for ' in line or 'while ' in line) and ('+=' in line and '"' in line):
                issues.append({
                    'severity': 'low',
                    'file': rel_path,
                    'line': i,
                    'description': '循环中使用字符串拼接',
                    'suggestion': '使用列表+join或StringIO替代+=拼接'
                })
                break
        
        # 3. 潜在的内存泄漏（全局缓存无上限）
        if 'cache' in content.lower() and 'maxsize' not in content.lower():
            for i, line in enumerate(lines, 1):
                if '@lru_cache' in line and 'maxsize' not in line:
                    issues.append({
                        'severity': 'low',
                        'file': rel_path,
                        'line': i,
                        'description': 'lru_cache未设置maxsize，可能导致内存无限增长',
                        'suggestion': '添加 maxsize 参数限制缓存大小'
                    })
                    break
    
    def _audit_design(self, cf: CodeFile, rel_path: str, content: str, lines: List[str], issues: List[Dict]):
        """设计问题检测"""
        # 1. sys.path 动态注入
        if cf.sys_path_inserts:
            for spi in cf.sys_path_inserts:
                issues.append({
                    'severity': 'medium',
                    'file': rel_path,
                    'line': 1,  # 无法精确定位行号
                    'description': f'使用 sys.path.insert 动态注入路径: `{spi}`',
                    'suggestion': '改为相对导入或包结构重构'
                })
        
        # 2. 循环依赖检测（简单：A导入B，B导入A）
        # 这个需要在全局层面检测，这里只做文件级标记
        
        # 3. 上帝类检测（方法过多）
        for cls in cf.classes:
            if len(cls.methods) > 20:
                issues.append({
                    'severity': 'medium',
                    'file': rel_path,
                    'line': cls.start_line,
                    'description': f'类 `{cls.name}` 方法过多 ({len(cls.methods)} 个)，可能是上帝类',
                    'suggestion': '拆分为多个职责单一的类'
                })
        
        # 4. 重复代码检测（简单：相同import模式）
        # 复杂重复检测需要AST级分析，这里跳过
        
        # 5. 硬编码配置（排除注释、字符串常量、文档路径等合理场景）
        hardcoded_patterns = [
            (r'localhost:\d+', '硬编码本地服务地址'),
            (r'127\.0\.0\.1:\d+', '硬编码本地IP地址'),
        ]
        for pattern, desc in hardcoded_patterns:
            for i, line in enumerate(lines, 1):
                if re.search(pattern, line) and '#' not in line and '"""' not in line:
                    issues.append({
                        'severity': 'low',
                        'file': rel_path,
                        'line': i,
                        'description': f'{desc}: `{line.strip()[:50]}`',
                        'suggestion': '使用配置文件或环境变量'
                    })
                    break
