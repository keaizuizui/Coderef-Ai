# -*- coding: utf-8 -*-
"""
工具函数
"""

import re
import os
import hashlib
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from loguru import logger


def is_code_file(file_path: str) -> bool:
    """判断是否为代码文件"""
    code_extensions = {
        '.py', '.js', '.ts', '.jsx', '.tsx', '.java', '.cpp', '.c', '.h',
        '.hpp', '.go', '.rs', '.rb', '.php', '.swift', '.kt', '.scala'
    }
    return Path(file_path).suffix.lower() in code_extensions


def get_file_language(file_path: str) -> str:
    """获取文件语言"""
    ext_map = {
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'typescript',
        '.java': 'java',
        '.cpp': 'cpp',
        '.c': 'c',
        '.go': 'go',
        '.rs': 'rust',
        '.rb': 'ruby',
        '.php': 'php'
    }
    ext = Path(file_path).suffix.lower()
    return ext_map.get(ext, 'unknown')


def count_code_lines(content: str) -> int:
    """统计代码行数（排除空行和注释）"""
    lines = content.split('\n')
    code_lines = 0
    
    in_multiline_comment = False
    
    for line in lines:
        stripped = line.strip()
        
        if not stripped:
            continue
        
        # 简单的注释检测
        if stripped.startswith(('#', '//')):
            continue
        
        code_lines += 1
    
    return code_lines


def extract_function_names(content: str, language: str = 'python') -> List[str]:
    """提取函数名"""
    functions = []
    
    if language == 'python':
        pattern = r'def\s+(\w+)\s*\('
    elif language in ['javascript', 'typescript']:
        pattern = r'function\s+(\w+)\s*\(|const\s+(\w+)\s*=\s*(?:async\s+)?function'
    else:
        pattern = r'\s+(\w+)\s*\([^)]*\)\s*\{'
    
    for match in re.finditer(pattern, content):
        name = match.group(1) or match.group(2)
        if name and not name.startswith('_'):
            functions.append(name)
    
    return functions


def extract_class_names(content: str, language: str = 'python') -> List[str]:
    """提取类名"""
    classes = []
    
    if language == 'python':
        pattern = r'class\s+(\w+)'
    elif language in ['javascript', 'typescript', 'java']:
        pattern = r'class\s+(\w+)'
    else:
        pattern = r'class\s+(\w+)'
    
    for match in re.finditer(pattern, content):
        name = match.group(1)
        if name:
            classes.append(name)
    
    return classes


def generate_file_hash(file_path: str) -> str:
    """生成文件哈希"""
    try:
        with open(file_path, 'rb') as f:
            return hashlib.md5(f.read()).hexdigest()
    except:
        return ''


def format_size(size_bytes: int) -> str:
    """格式化文件大小"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024
    return f"{size_bytes:.1f} TB"


def format_timestamp(timestamp: float) -> str:
    """格式化时间戳"""
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')


def sanitize_filename(filename: str) -> str:
    """清理文件名"""
    return re.sub(r'[<>:"/\\|?*]', '_', filename)


def find_git_root(path: str) -> Optional[str]:
    """查找Git根目录"""
    current = Path(path).resolve()
    
    while current != current.parent:
        if (current / '.git').exists():
            return str(current)
        current = current.parent
    
    return None


def get_project_name(path: str) -> str:
    """获取项目名称"""
    git_root = find_git_root(path)
    if git_root:
        return Path(git_root).name
    return Path(path).name


def detect_framework(content: str) -> List[str]:
    """检测使用的框架"""
    frameworks = []
    
    indicators = {
        'FastAPI': ['from fastapi', 'FastAPI('],
        'Flask': ['from flask', 'Flask('],
        'Django': ['from django', 'django.'],
        'React': ['react', 'React'],
        'Vue': ['vue', 'Vue'],
        'Angular': ['@angular', 'angular'],
        'PyTorch': ['import torch', 'torch.'],
        'TensorFlow': ['import tensorflow', 'tf.'],
        'Pandas': ['import pandas', 'pd.'],
        'NumPy': ['import numpy', 'np.'],
    }
    
    for framework, patterns in indicators.items():
        if any(p in content for p in patterns):
            frameworks.append(framework)
    
    return frameworks


def truncate_text(text: str, max_length: int = 200) -> str:
    """截断文本"""
    if len(text) <= max_length:
        return text
    return text[:max_length] + '...'


def clean_markdown(text: str) -> str:
    """清理Markdown格式"""
    # 移除代码块标记
    text = re.sub(r'```[\w]*\n', '', text)
    text = re.sub(r'```', '', text)
    # 移除标题标记
    text = re.sub(r'^#+\s*', '', text, flags=re.MULTILINE)
    # 移除列表标记
    text = re.sub(r'^[-*]\s*', '', text, flags=re.MULTILINE)
    return text.strip()
