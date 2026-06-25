# -*- coding: utf-8 -*-
"""
配置管理
"""

import os
import json
from pathlib import Path
from typing import Dict, Any, Optional
from dataclasses import dataclass, asdict

from loguru import logger


@dataclass
class AppConfig:
    """应用配置"""
    # LLM配置
    llm_provider: str = "ollama"
    llm_api_key: str = "ollama"
    llm_base_url: str = "http://localhost:11434/v1"
    llm_model: str = "llama2"
    llm_temperature: float = 0.7
    llm_max_tokens: int = 2048
    
    # 项目配置
    project_path: str = ""
    
    # 搜索配置
    search_frequency: str = "disabled"
    search_keywords: str = "AI, LLM, 代码优化"
    search_result_count: int = 5


class ConfigManager:
    """配置管理器
    
    优先从 cache/config.json 加载（用户专属），
    其次从 config/config.json 加载（默认模板）。
    开源时删除 cache/ 目录即可清除所有用户数据。
    """
    
    def __init__(self, config_dir: Optional[str] = None):
        if config_dir is None:
            config_dir = Path(__file__).parent
        
        self.config_file = Path(config_dir) / "config.json"
        self.config = AppConfig()
        self.load_config()
    
    def _get_cache_config_path(self) -> Optional[Path]:
        """获取 cache/ 中的配置文件路径"""
        cache_config = Path(__file__).parent.parent / "cache" / "config.json"
        if cache_config.exists():
            return cache_config
        return None
    
    def load_config(self):
        """加载配置 —— 优先从 cache/，其次从 config/"""
        try:
            # 优先加载 cache/ 中的配置
            cache_path = self._get_cache_config_path()
            load_path = cache_path or self.config_file
            
            if load_path.exists():
                with open(load_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                for key, value in data.items():
                    if hasattr(self.config, key):
                        setattr(self.config, key, value)
                
                logger.debug(f"配置已加载: {load_path}")
            else:
                self.save_config()
                logger.debug("创建默认配置文件")
        
        except Exception as e:
            logger.error(f"加载配置失败: {e}")
    
    def save_config(self):
        """保存配置到 cache/"""
        try:
            # 保存到 cache/
            cache_dir = Path(__file__).parent.parent / "cache"
            cache_dir.mkdir(parents=True, exist_ok=True)
            cache_file = cache_dir / "config.json"
            
            with open(cache_file, 'w', encoding='utf-8') as f:
                json.dump(asdict(self.config), f, indent=2, ensure_ascii=False)
            
            logger.debug(f"配置已保存到: {cache_file}")
        except Exception as e:
            logger.error(f"保存配置失败: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """获取配置项"""
        return getattr(self.config, key, default)
    
    def set(self, key: str, value: Any):
        """设置配置项"""
        if hasattr(self.config, key):
            setattr(self.config, key, value)
            self.save_config()
    
    def get_llm_config(self) -> Dict[str, Any]:
        """获取LLM配置"""
        return {
            "provider": self.config.llm_provider,
            "api_key": self.config.llm_api_key,
            "base_url": self.config.llm_base_url,
            "model": self.config.llm_model,
            "temperature": self.config.llm_temperature,
            "max_tokens": self.config.llm_max_tokens
        }
    
    def update_llm_config(self, config: Dict[str, Any]):
        """更新LLM配置"""
        for key, value in config.items():
            attr_name = f"llm_{key}"
            if hasattr(self.config, attr_name):
                setattr(self.config, attr_name, value)
        self.save_config()


# 全局配置实例
config_manager = ConfigManager()
