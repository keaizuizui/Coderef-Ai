# -*- coding: utf-8 -*-
"""
项目成熟度审计器 —— 面向不懂代码的单人 AI 辅助开发者

检测项目是否具备专业软件开发的基本要素，帮助用户发现"缺失了什么"：
不需要用户知道"应该有什么"，审计器自动检查并给出通俗解释。

检测维度：
1. 测试设施 —— 有测试框架吗？有测试目录吗？有测试覆盖率工具吗？
2. CI/CD —— 有自动化流水线吗？
3. 线上监控 —— 有日志系统吗？有错误追踪吗？有健康检查吗？
4. 配置管理 —— 有环境变量管理吗？敏感信息泄露了吗？
5. 错误处理 —— 有全局异常处理器吗？有空异常处理吗？
6. 依赖管理 —— 有依赖锁文件吗？依赖有已知漏洞吗？
7. 代码质量 —— 有类型检查吗？有格式化工具吗？有 pre-commit 吗？
8. 文档 —— 有 README 吗？有 API 文档吗？

作者: CodeRef Team
版本: v1.0
"""

import os
import re
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict


# ═══════════════════════════════════════════════════════════════════
# 数据结构
# ═══════════════════════════════════════════════════════════════════

@dataclass
class MaturityCheck:
    """单条成熟度检查结果"""
    check_id: str
    category: str  # testing / cicd / monitoring / config / error_handling / deps / quality / docs
    name: str  # 检查项名称（中文）
    status: str  # pass / fail / warn / missing
    detail: str  # 详细说明
    suggestion: str  # 改进建议（通俗语言）
    evidence: str = ""  # 发现的证据（通过时）


@dataclass
class MaturityReport:
    """成熟度审计报告"""
    project_path: str
    project_name: str
    project_type: str = ""  # web / cli / agent / unknown
    framework: str = ""  # FastAPI / Django / Flask / None
    checks: List[MaturityCheck] = field(default_factory=list)
    score: int = 0
    grade: str = "F"


# ═══════════════════════════════════════════════════════════════════
# 检查器
# ═══════════════════════════════════════════════════════════════════

class ProjectMaturityChecker:
    """项目成熟度审计器"""

    def __init__(self):
        pass

    # ─── 辅助方法 ───

    def _file_exists(self, project_path: str, pattern: str) -> bool:
        """检查项目根目录下是否存在匹配的文件/目录"""
        target = os.path.join(project_path, pattern)
        return os.path.exists(target)

    def _glob_exists(self, project_path: str, pattern: str) -> bool:
        """检查是否存在 glob 匹配的文件"""
        import glob
        matches = glob.glob(os.path.join(project_path, pattern))
        return len(matches) > 0

    def _get_deps(self, project_path: str) -> List[str]:
        """获取项目依赖列表（从 requirements.txt / pyproject.toml）"""
        deps = []
        req_path = os.path.join(project_path, "requirements.txt")
        if os.path.exists(req_path):
            try:
                with open(req_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip().split("#")[0].strip()
                        if line and not line.startswith("-"):
                            deps.append(line.lower())
            except (OSError, IOError):
                pass
        return deps

    def _has_dep(self, deps: List[str], keyword: str) -> bool:
        """检查依赖列表中是否包含某关键词"""
        return any(keyword in d for d in deps)

    def _scan_content(self, project_path: str, pattern: str, file_ext: str = ".py") -> bool:
        """扫描项目文件内容，检查是否包含某模式"""
        rgx = re.compile(pattern, re.IGNORECASE)
        for root, dirs, files in os.walk(project_path):
            dirs[:] = [d for d in dirs if not d.startswith(".") and d not in (
                "__pycache__", "node_modules", ".git", "venv", ".venv", "env",
                "Lib", "lib", "site-packages", "dist-packages", "cache", "data",
            )]
            for f in files:
                if not f.endswith(file_ext):
                    continue
                try:
                    with open(os.path.join(root, f), "r", encoding="utf-8", errors="ignore") as fh:
                        if rgx.search(fh.read(50000)):
                            return True
                except (OSError, IOError):
                    continue
        return False

    def _detect_framework(self, project_path: str) -> str:
        """检测项目使用的框架"""
        deps = self._get_deps(project_path)
        if self._has_dep(deps, "fastapi"):
            return "FastAPI"
        if self._has_dep(deps, "django"):
            return "Django"
        if self._has_dep(deps, "flask"):
            return "Flask"
        if self._has_dep(deps, "streamlit"):
            return "Streamlit"
        if self._has_dep(deps, "gradio"):
            return "Gradio"
        if self._has_dep(deps, "langchain") or self._has_dep(deps, "openai") or self._has_dep(deps, "anthropic"):
            return "AI Agent"
        return ""

    def _detect_project_type(self, project_path: str, framework: str) -> str:
        """检测项目类型"""
        if framework in ("FastAPI", "Django", "Flask"):
            return "web"
        if framework == "AI Agent":
            return "agent"
        if framework in ("Streamlit", "Gradio"):
            return "web"
        # 检查是否有 CLI 入口
        if self._file_exists(project_path, "setup.py") or self._file_exists(project_path, "pyproject.toml"):
            return "cli"
        return "unknown"

    # ─── 主检测方法 ───

    def check(self, project_path: str) -> MaturityReport:
        """执行项目成熟度审计"""
        project_path = os.path.abspath(project_path)
        project_name = os.path.basename(project_path)
        framework = self._detect_framework(project_path)
        project_type = self._detect_project_type(project_path, framework)
        deps = self._get_deps(project_path)

        checks = []

        # 1. 测试设施
        checks.extend(self._check_testing(project_path, deps, framework))
        # 2. CI/CD
        checks.extend(self._check_cicd(project_path))
        # 3. 线上监控
        checks.extend(self._check_monitoring(project_path, deps, project_type))
        # 4. 配置管理
        checks.extend(self._check_config(project_path, deps))
        # 5. 错误处理
        checks.extend(self._check_error_handling(project_path, framework))
        # 6. 依赖管理
        checks.extend(self._check_dependencies(project_path, deps))
        # 7. 代码质量
        checks.extend(self._check_code_quality(project_path, deps))
        # 8. 文档
        checks.extend(self._check_documentation(project_path, framework))

        # 计算评分
        total = len(checks)
        passed = sum(1 for c in checks if c.status == "pass")
        warn = sum(1 for c in checks if c.status == "warn")

        if total == 0:
            score = 100
        else:
            score = int((passed + warn * 0.5) / total * 100)

        if score >= 90:
            grade = "A"
        elif score >= 75:
            grade = "B"
        elif score >= 60:
            grade = "C"
        elif score >= 40:
            grade = "D"
        else:
            grade = "F"

        return MaturityReport(
            project_path=project_path,
            project_name=project_name,
            project_type=project_type,
            framework=framework,
            checks=checks,
            score=score,
            grade=grade,
        )

    # ─── 1. 测试设施 ───

    def _check_testing(self, project_path: str, deps: List[str], framework: str) -> List[MaturityCheck]:
        checks = []

        # 测试框架
        has_pytest = self._has_dep(deps, "pytest")
        has_unittest = self._scan_content(project_path, r"import\s+unittest|from\s+unittest")
        has_test_dir = self._file_exists(project_path, "tests") or self._file_exists(project_path, "test")
        has_test_files = self._glob_exists(project_path, "**/test_*.py") or self._glob_exists(project_path, "**/*_test.py")

        if has_pytest or has_unittest:
            checks.append(MaturityCheck(
                check_id="MAT-TEST-01", category="testing", name="测试框架",
                status="pass", detail=f"检测到测试框架：{'pytest' if has_pytest else 'unittest'}",
                suggestion="", evidence=f"pytest" if has_pytest else "unittest",
            ))
        else:
            checks.append(MaturityCheck(
                check_id="MAT-TEST-01", category="testing", name="测试框架",
                status="fail", detail="未检测到任何测试框架（pytest 或 unittest）",
                suggestion="在 requirements.txt 中添加 pytest，然后创建 tests/ 目录，写几个简单的测试用例",
            ))

        if has_test_dir or has_test_files:
            checks.append(MaturityCheck(
                check_id="MAT-TEST-02", category="testing", name="测试文件",
                status="pass", detail="检测到测试文件或目录",
                suggestion="", evidence="tests/" if has_test_dir else "test_*.py",
            ))
        else:
            checks.append(MaturityCheck(
                check_id="MAT-TEST-02", category="testing", name="测试文件",
                status="fail", detail="未检测到测试目录或测试文件",
                suggestion="创建 tests/ 目录，为每个核心模块写一个 test_<模块名>.py 文件",
            ))

        # 测试覆盖率
        has_cov = self._has_dep(deps, "pytest-cov") or self._has_dep(deps, "coverage")
        if has_cov:
            checks.append(MaturityCheck(
                check_id="MAT-TEST-03", category="testing", name="测试覆盖率",
                status="pass", detail="检测到测试覆盖率工具",
                suggestion="", evidence="pytest-cov/coverage",
            ))
        else:
            checks.append(MaturityCheck(
                check_id="MAT-TEST-03", category="testing", name="测试覆盖率",
                status="warn", detail="未检测到测试覆盖率工具（pytest-cov 或 coverage）",
                suggestion="添加 pytest-cov 到 requirements.txt，运行 pytest --cov 查看测试覆盖率",
            ))

        return checks

    # ─── 2. CI/CD ───

    def _check_cicd(self, project_path: str) -> List[MaturityCheck]:
        checks = []

        has_github_actions = self._glob_exists(project_path, ".github/workflows/*.yml")
        has_gitlab_ci = self._file_exists(project_path, ".gitlab-ci.yml")
        has_jenkins = self._file_exists(project_path, "Jenkinsfile")
        has_dockerfile = self._file_exists(project_path, "Dockerfile")
        has_makefile = self._file_exists(project_path, "Makefile")

        if has_github_actions or has_gitlab_ci or has_jenkins:
            ci_type = "GitHub Actions" if has_github_actions else "GitLab CI" if has_gitlab_ci else "Jenkins"
            checks.append(MaturityCheck(
                check_id="MAT-CI-01", category="cicd", name="CI/CD 流水线",
                status="pass", detail=f"检测到 {ci_type} 自动化流水线",
                suggestion="", evidence=ci_type,
            ))
        else:
            checks.append(MaturityCheck(
                check_id="MAT-CI-01", category="cicd", name="CI/CD 流水线",
                status="fail", detail="未检测到任何 CI/CD 自动化流水线",
                suggestion="创建 .github/workflows/test.yml，配置 GitHub Actions 自动运行测试",
            ))

        if has_dockerfile:
            checks.append(MaturityCheck(
                check_id="MAT-CI-02", category="cicd", name="容器化",
                status="pass", detail="检测到 Dockerfile",
                suggestion="", evidence="Dockerfile",
            ))
        else:
            checks.append(MaturityCheck(
                check_id="MAT-CI-02", category="cicd", name="容器化",
                status="warn", detail="未检测到 Dockerfile",
                suggestion="创建 Dockerfile 使项目可容器化部署，便于在不同环境运行",
            ))

        if has_makefile:
            checks.append(MaturityCheck(
                check_id="MAT-CI-03", category="cicd", name="任务自动化",
                status="pass", detail="检测到 Makefile",
                suggestion="", evidence="Makefile",
            ))
        else:
            checks.append(MaturityCheck(
                check_id="MAT-CI-03", category="cicd", name="任务自动化",
                status="warn", detail="未检测到 Makefile 或类似任务自动化文件",
                suggestion="创建 Makefile 或使用 setup.bat 封装常用命令（测试、运行、部署）",
            ))

        return checks

    # ─── 3. 线上监控 ───

    def _check_monitoring(self, project_path: str, deps: List[str], project_type: str) -> List[MaturityCheck]:
        checks = []

        # 日志系统
        has_loguru = self._has_dep(deps, "loguru")
        has_structlog = self._has_dep(deps, "structlog")
        has_logging_config = self._scan_content(project_path, r"logging\.(?:basicConfig|getLogger|config)")
        has_log_config_file = self._file_exists(project_path, "logging.conf") or self._file_exists(project_path, "log_config.yaml")

        if has_loguru or has_structlog or has_logging_config or has_log_config_file:
            log_type = "loguru" if has_loguru else "structlog" if has_structlog else "logging"
            checks.append(MaturityCheck(
                check_id="MAT-MON-01", category="monitoring", name="日志系统",
                status="pass", detail=f"检测到日志系统：{log_type}",
                suggestion="", evidence=log_type,
            ))
        else:
            checks.append(MaturityCheck(
                check_id="MAT-MON-01", category="monitoring", name="日志系统",
                status="fail", detail="未检测到任何日志系统",
                suggestion="安装 loguru（pip install loguru），在代码中使用 logger.info/error 记录关键操作",
            ))

        # 错误追踪
        has_sentry = self._has_dep(deps, "sentry-sdk")
        if has_sentry:
            checks.append(MaturityCheck(
                check_id="MAT-MON-02", category="monitoring", name="错误追踪",
                status="pass", detail="检测到 Sentry 错误追踪",
                suggestion="", evidence="sentry-sdk",
            ))
        else:
            checks.append(MaturityCheck(
                check_id="MAT-MON-02", category="monitoring", name="错误追踪",
                status="warn", detail="未检测到错误追踪服务（如 Sentry）",
                suggestion="集成 Sentry 自动捕获和报告线上错误，让你第一时间知道出问题了",
            ))

        # 健康检查（仅 Web/Agent 类型）
        if project_type in ("web", "agent"):
            has_health = (
                self._scan_content(project_path, r'@.*\.(?:get|route)\s*\(\s*["\']/(?:health|healthz|ready|ping)["\']')
                or self._scan_content(project_path, r'def\s+(?:health|health_check|healthz|ready|liveness)')
            )
            if has_health:
                checks.append(MaturityCheck(
                    check_id="MAT-MON-03", category="monitoring", name="健康检查",
                    status="pass", detail="检测到健康检查端点",
                    suggestion="", evidence="/health",
                ))
            else:
                checks.append(MaturityCheck(
                    check_id="MAT-MON-03", category="monitoring", name="健康检查",
                    status="fail", detail="未检测到健康检查端点（/health 或 /ready）",
                    suggestion="添加一个 /health 端点，返回 {status: ok}，方便监控工具检查服务是否正常运行",
                ))

        return checks

    # ─── 4. 配置管理 ───

    def _check_config(self, project_path: str, deps: List[str]) -> List[MaturityCheck]:
        checks = []

        # 环境变量管理
        has_dotenv = self._has_dep(deps, "python-dotenv")
        has_env_file = self._file_exists(project_path, ".env") or self._file_exists(project_path, ".env.example")
        has_env_template = self._file_exists(project_path, ".env.example") or self._file_exists(project_path, ".env.template")

        if has_dotenv or has_env_file:
            checks.append(MaturityCheck(
                check_id="MAT-CFG-01", category="config", name="环境变量",
                status="pass", detail="检测到环境变量管理",
                suggestion="", evidence="python-dotenv" if has_dotenv else ".env",
            ))
        else:
            checks.append(MaturityCheck(
                check_id="MAT-CFG-01", category="config", name="环境变量",
                status="fail", detail="未检测到环境变量管理（python-dotenv 或 .env 文件）",
                suggestion="安装 python-dotenv，创建 .env 文件存放 API Key 等敏感配置，不要硬编码在代码里",
            ))

        if has_env_template:
            checks.append(MaturityCheck(
                check_id="MAT-CFG-02", category="config", name="配置模板",
                status="pass", detail="检测到 .env.example 配置模板",
                suggestion="", evidence=".env.example",
            ))
        else:
            checks.append(MaturityCheck(
                check_id="MAT-CFG-02", category="config", name="配置模板",
                status="warn", detail="未检测到 .env.example 配置模板",
                suggestion="创建 .env.example 文件，列出所有需要的环境变量（不含真实值），方便他人部署",
            ))

        # 敏感信息泄露
        has_secrets_in_code = self._scan_content(project_path, r'(?:api_key|api_secret|password|secret|token)\s*[:=]\s*["\']\w{10,}')
        if has_secrets_in_code:
            checks.append(MaturityCheck(
                check_id="MAT-CFG-03", category="config", name="敏感信息泄露",
                status="fail", detail="检测到代码中可能包含硬编码的 API Key 或密码",
                suggestion="将敏感信息移到 .env 文件，使用 os.getenv() 读取，确保 .env 已加入 .gitignore",
            ))
        else:
            checks.append(MaturityCheck(
                check_id="MAT-CFG-03", category="config", name="敏感信息泄露",
                status="pass", detail="未检测到硬编码的敏感信息",
                suggestion="",
            ))

        # .gitignore
        has_gitignore = self._file_exists(project_path, ".gitignore")
        if has_gitignore:
            # 检查 .gitignore 是否包含常见忽略项
            try:
                with open(os.path.join(project_path, ".gitignore"), "r", encoding="utf-8", errors="ignore") as f:
                    gitignore_content = f.read().lower()
                has_env_ignored = ".env" in gitignore_content and "__pycache__" in gitignore_content
                if has_env_ignored:
                    checks.append(MaturityCheck(
                        check_id="MAT-CFG-04", category="config", name=".gitignore",
                        status="pass", detail=".gitignore 配置正确，已忽略 .env 和 __pycache__",
                        suggestion="",
                    ))
                else:
                    checks.append(MaturityCheck(
                        check_id="MAT-CFG-04", category="config", name=".gitignore",
                        status="warn", detail=".gitignore 存在但可能不完整，缺少 .env 或 __pycache__",
                        suggestion="在 .gitignore 中添加 .env 和 __pycache__/，防止敏感信息泄露",
                    ))
            except (OSError, IOError):
                pass
        else:
            checks.append(MaturityCheck(
                check_id="MAT-CFG-04", category="config", name=".gitignore",
                status="fail", detail="未检测到 .gitignore 文件",
                suggestion="创建 .gitignore 文件，添加 .env、__pycache__/、*.pyc 等，防止意外提交敏感文件",
            ))

        return checks

    # ─── 5. 错误处理 ───

    def _check_error_handling(self, project_path: str, framework: str) -> List[MaturityCheck]:
        checks = []

        # 全局异常处理器（仅 Web 框架）
        if framework in ("FastAPI", "Django", "Flask"):
            if framework == "FastAPI":
                has_global_handler = self._scan_content(project_path, r'@.*\.exception_handler|add_exception_handler')
            elif framework == "Django":
                has_global_handler = self._scan_content(project_path, r'handler500|handler400|middleware.*process_exception')
            else:
                has_global_handler = self._scan_content(project_path, r'@app\.errorhandler|register_error_handler')

            if has_global_handler:
                checks.append(MaturityCheck(
                    check_id="MAT-ERR-01", category="error_handling", name="全局异常处理",
                    status="pass", detail=f"检测到 {framework} 全局异常处理器",
                    suggestion="",
                ))
            else:
                checks.append(MaturityCheck(
                    check_id="MAT-ERR-01", category="error_handling", name="全局异常处理",
                    status="fail", detail=f"未检测到 {framework} 全局异常处理器",
                    suggestion=f"添加 {framework} 全局异常处理器，统一捕获未处理的异常，返回友好的错误信息",
                ))

        return checks

    # ─── 6. 依赖管理 ───

    def _check_dependencies(self, project_path: str, deps: List[str]) -> List[MaturityCheck]:
        checks = []

        # 依赖文件
        has_req = self._file_exists(project_path, "requirements.txt")
        has_pyproject = self._file_exists(project_path, "pyproject.toml")

        if has_req or has_pyproject:
            dep_type = "requirements.txt" if has_req else "pyproject.toml"
            checks.append(MaturityCheck(
                check_id="MAT-DEP-01", category="deps", name="依赖声明",
                status="pass", detail=f"检测到依赖管理文件：{dep_type}",
                suggestion="", evidence=dep_type,
            ))
        else:
            checks.append(MaturityCheck(
                check_id="MAT-DEP-01", category="deps", name="依赖声明",
                status="fail", detail="未检测到 requirements.txt 或 pyproject.toml",
                suggestion="创建 requirements.txt 列出所有 Python 依赖，方便他人安装和部署",
            ))

        # 依赖锁文件
        has_lock = self._file_exists(project_path, "requirements.txt") and not self._file_exists(project_path, "pyproject.toml")
        has_pipfile_lock = self._file_exists(project_path, "Pipfile.lock")
        has_poetry_lock = self._file_exists(project_path, "poetry.lock")

        if has_pipfile_lock or has_poetry_lock:
            lock_type = "Pipfile.lock" if has_pipfile_lock else "poetry.lock"
            checks.append(MaturityCheck(
                check_id="MAT-DEP-02", category="deps", name="依赖锁定",
                status="pass", detail=f"检测到依赖锁文件：{lock_type}",
                suggestion="", evidence=lock_type,
            ))
        else:
            checks.append(MaturityCheck(
                check_id="MAT-DEP-02", category="deps", name="依赖锁定",
                status="warn", detail="未检测到依赖锁文件（Pipfile.lock 或 poetry.lock）",
                suggestion="使用 pip freeze > requirements.txt 锁定依赖版本，防止不同环境依赖不一致导致问题",
            ))

        return checks

    # ─── 7. 代码质量 ───

    def _check_code_quality(self, project_path: str, deps: List[str]) -> List[MaturityCheck]:
        checks = []

        # 类型检查
        has_mypy = self._has_dep(deps, "mypy") or self._file_exists(project_path, "mypy.ini") or self._file_exists(project_path, "pyproject.toml")
        if has_mypy:
            checks.append(MaturityCheck(
                check_id="MAT-QLY-01", category="quality", name="类型检查",
                status="pass", detail="检测到 mypy 类型检查器",
                suggestion="", evidence="mypy",
            ))
        else:
            checks.append(MaturityCheck(
                check_id="MAT-QLY-01", category="quality", name="类型检查",
                status="warn", detail="未检测到 mypy 类型检查器",
                suggestion="安装 mypy 并添加类型注解，可以在运行前发现类型错误，减少 Bug",
            ))

        # 代码格式化
        has_ruff = self._has_dep(deps, "ruff")
        has_black = self._has_dep(deps, "black")
        has_pre_commit = self._file_exists(project_path, ".pre-commit-config.yaml")

        if has_ruff or has_black:
            fmt_tool = "ruff" if has_ruff else "black"
            checks.append(MaturityCheck(
                check_id="MAT-QLY-02", category="quality", name="代码格式化",
                status="pass", detail=f"检测到代码格式化工具：{fmt_tool}",
                suggestion="", evidence=fmt_tool,
            ))
        else:
            checks.append(MaturityCheck(
                check_id="MAT-QLY-02", category="quality", name="代码格式化",
                status="warn", detail="未检测到代码格式化工具（ruff 或 black）",
                suggestion="安装 ruff，运行 ruff format 自动格式化代码，保持代码风格一致",
            ))

        if has_pre_commit:
            checks.append(MaturityCheck(
                check_id="MAT-QLY-03", category="quality", name="Pre-commit 钩子",
                status="pass", detail="检测到 .pre-commit-config.yaml",
                suggestion="", evidence="pre-commit",
            ))
        else:
            checks.append(MaturityCheck(
                check_id="MAT-QLY-03", category="quality", name="Pre-commit 钩子",
                status="warn", detail="未检测到 pre-commit 配置",
                suggestion="配置 pre-commit 钩子，在每次提交前自动运行格式化和类型检查，防止提交有问题的代码",
            ))

        return checks

    # ─── 8. 文档 ───

    def _check_documentation(self, project_path: str, framework: str) -> List[MaturityCheck]:
        checks = []

        # README
        has_readme = self._file_exists(project_path, "README.md") or self._file_exists(project_path, "README.txt")
        if has_readme:
            readme_file = "README.md" if self._file_exists(project_path, "README.md") else "README.txt"
            # 检查 README 是否足够详细（> 500 字符）
            try:
                with open(os.path.join(project_path, readme_file), "r", encoding="utf-8", errors="ignore") as f:
                    readme_len = len(f.read())
                if readme_len > 500:
                    checks.append(MaturityCheck(
                        check_id="MAT-DOC-01", category="docs", name="README 文档",
                        status="pass", detail=f"README 文档存在且内容充足（{readme_len} 字符）",
                        suggestion="", evidence=readme_file,
                    ))
                else:
                    checks.append(MaturityCheck(
                        check_id="MAT-DOC-01", category="docs", name="README 文档",
                        status="warn", detail=f"README 存在但内容较简短（{readme_len} 字符）",
                        suggestion="完善 README，至少包含：项目简介、安装步骤、快速开始、主要功能说明",
                    ))
            except (OSError, IOError):
                pass
        else:
            checks.append(MaturityCheck(
                check_id="MAT-DOC-01", category="docs", name="README 文档",
                status="fail", detail="未检测到 README.md 文件",
                suggestion="创建 README.md，说明项目是什么、如何安装、如何使用，方便他人和自己日后回顾",
            ))

        # API 文档（仅 Web 框架）
        if framework == "FastAPI":
            # FastAPI 自带 /docs，检查是否启用
            if self._scan_content(project_path, r'FastAPI\s*\(.*docs_url'):
                checks.append(MaturityCheck(
                    check_id="MAT-DOC-02", category="docs", name="API 文档",
                    status="pass", detail="FastAPI 自动生成 Swagger 文档（/docs）",
                    suggestion="",
                ))
            else:
                checks.append(MaturityCheck(
                    check_id="MAT-DOC-02", category="docs", name="API 文档",
                    status="warn", detail="FastAPI 项目，确认 /docs 端点是否可访问",
                    suggestion="访问 http://localhost:8000/docs 查看自动生成的 API 文档",
                ))

        return checks

    # ─── 报告生成 ───

    def to_report(self, report: MaturityReport) -> str:
        """生成 Markdown 格式的成熟度审计报告"""
        lines = [
            f"# 项目成熟度审计",
            f"",
            f"> 项目: `{report.project_path}`",
            f"> 项目名称: **{report.project_name}**",
        ]

        if report.project_type:
            pt_labels = {"web": "Web 应用", "agent": "AI Agent", "cli": "命令行工具", "unknown": "未知类型"}
            lines.append(f"> 项目类型: {pt_labels.get(report.project_type, report.project_type)}")
        if report.framework:
            lines.append(f"> 识别框架: **{report.framework}**")

        lines.append("")

        # 评分
        by_category = defaultdict(list)
        for c in report.checks:
            by_category[c.category].append(c)

        passed = sum(1 for c in report.checks if c.status == "pass")
        failed = sum(1 for c in report.checks if c.status == "fail")
        warn = sum(1 for c in report.checks if c.status == "warn")
        total = len(report.checks)

        grade_icon = {"A": "🟢", "B": "🔵", "C": "🟡", "D": "🟠", "F": "🔴"}.get(report.grade, "⚪")

        lines.append("## 成熟度评分")
        lines.append("")
        lines.append(f"| 评分 | 等级 | 通过 | 警告 | 缺失 | 总计 |")
        lines.append(f"|------|------|------|------|------|------|")
        lines.append(f"| **{report.score}/100** | {grade_icon} **{report.grade}** | {passed} | {warn} | {failed} | {total} |")
        lines.append("")

        if report.score >= 90:
            lines.append("✅ 项目成熟度很高，已具备专业软件开发的大部分要素。")
        elif report.score >= 75:
            lines.append("⚠️ 项目基本成熟，但还有几个关键缺失需要补上。")
        elif report.score >= 60:
            lines.append("⚠️ 项目处于及格线，建议优先解决下面标记为「缺失」的检查项。")
        elif report.score >= 40:
            lines.append("🔴 项目成熟度较低，缺少多个专业开发要素，建议尽快补齐。")
        else:
            lines.append("🔴 项目成熟度很低，缺少大量专业开发基础。别担心，下面每一项都给了通俗的改进建议。")

        lines.append("")

        # 类别汇总
        lines.append("## 类别汇总")
        lines.append("")

        cat_labels = {
            "testing": "测试设施",
            "cicd": "CI/CD 流水线",
            "monitoring": "线上监控",
            "config": "配置管理",
            "error_handling": "错误处理",
            "deps": "依赖管理",
            "quality": "代码质量",
            "docs": "文档",
        }
        cat_descriptions = {
            "testing": "自动化测试帮你确认代码改动不会破坏已有功能",
            "cicd": "自动化流水线帮你自动测试和部署，不用每次手动操作",
            "monitoring": "日志和监控帮你在出问题时第一时间发现和定位",
            "config": "配置管理防止敏感信息泄露，方便在不同环境切换",
            "error_handling": "错误处理防止程序崩溃时用户看到不友好的报错",
            "deps": "依赖管理确保项目在不同环境能正常运行",
            "quality": "代码质量工具在提交代码前自动检查问题",
            "docs": "文档帮助他人（和未来的你）理解项目",
        }

        for cat_key in ["testing", "cicd", "monitoring", "config", "error_handling", "deps", "quality", "docs"]:
            cat_checks = by_category.get(cat_key, [])
            if not cat_checks:
                continue
            cat_passed = sum(1 for c in cat_checks if c.status == "pass")
            cat_total = len(cat_checks)
            cat_icon = "✅" if cat_passed == cat_total else "⚠️" if cat_passed > 0 else "❌"
            lines.append(f"| {cat_icon} {cat_labels.get(cat_key, cat_key)} | {cat_passed}/{cat_total} | {cat_descriptions.get(cat_key, '')} |")

        lines.append("")

        # 详细检查结果
        lines.append("## 详细检查结果")
        lines.append("")

        for cat_key in ["testing", "cicd", "monitoring", "config", "error_handling", "deps", "quality", "docs"]:
            cat_checks = by_category.get(cat_key, [])
            if not cat_checks:
                continue
            lines.append(f"### {cat_labels.get(cat_key, cat_key)}")
            lines.append("")
            lines.append("| 状态 | 检查项 | 详情 | 建议 |")
            lines.append("|------|--------|------|------|")

            for c in cat_checks:
                if c.status == "pass":
                    icon = "✅"
                elif c.status == "fail":
                    icon = "❌ 缺失"
                else:
                    icon = "⚠️ 警告"

                detail = c.detail[:100]
                if c.evidence and c.status == "pass":
                    detail += f"（{c.evidence}）"

                suggestion = c.suggestion[:120] if c.suggestion else "-"

                lines.append(f"| {icon} | {c.name} | {detail} | {suggestion} |")

            lines.append("")

        lines.append("---")
        lines.append("")
        lines.append("### 关于项目成熟度审计")
        lines.append("")
        lines.append("本报告面向不懂代码的 AI 辅助开发者设计。")
        lines.append("每一项检查都对照专业软件开发流程，帮助你发现项目中缺失的关键要素。")
        lines.append("")
        lines.append("每条建议都给出了通俗的操作步骤，跟着做就能提升项目成熟度。")
        lines.append("")
        lines.append("*扫描由 CodeRef Project Maturity Checker 执行*")

        return "\n".join(lines)