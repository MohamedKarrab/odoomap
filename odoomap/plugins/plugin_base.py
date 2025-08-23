#!/usr/bin/env python3
"""
Base plugin structure and metadata system for OdooMap plugins
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum

class PluginCategory(Enum):
    """Plugin categories for organization"""
    SECURITY = "security"
    ENUMERATION = "enumeration"
    EXPLOITATION = "exploitation"
    INFORMATION = "information"
    REPORTING = "reporting"

@dataclass
class PluginMetadata:
    """Simple metadata structure for plugins"""
    name: str
    description: str
    author: str
    version: str
    category: PluginCategory
    requires_auth: bool = False
    requires_connection: bool = True
    external_dependencies: Optional[List[str]] = None
    
    def __post_init__(self):
        if self.external_dependencies is None:
            self.external_dependencies = []

class BasePlugin(ABC):
    """Base class for all OdooMap plugins"""
    
    def __init__(self):
        self.metadata = self.get_metadata()
    
    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """Return plugin metadata"""
        pass
    
    @abstractmethod
    def run(self, target_url: str, database: Optional[str] = None, 
            username: Optional[str] = None, password: Optional[str] = None, 
            connection: Optional[Any] = None) -> str:
        """
        Main plugin execution method
        
        Args:
            target_url: Target Odoo instance URL
            database: Database name (optional)
            username: Username for authentication (optional)
            password: Password for authentication (optional)
            connection: Active connection object (optional)
            
        Returns:
            String result of plugin execution
        """
        pass
    
    def validate_requirements(self, connection: Optional[Any] = None, 
                            username: Optional[str] = None, 
                            password: Optional[str] = None) -> bool:
        """Check if plugin requirements are met"""
        if self.metadata.requires_connection and connection is None:
            return False
        if self.metadata.requires_auth and (username is None or password is None):
            return False
        return True

# Backward compatibility - keep the old Plugin name
Plugin = BasePlugin
