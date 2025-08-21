import os
import importlib
from typing import Dict, Any

def list_available_plugins():
    """Just list plugin names without loading them"""
    plugin_dir = os.path.join(os.path.dirname(__file__), "plugins")
    if not os.path.exists(plugin_dir):
        return []
    return [f[:-3] for f in os.listdir(plugin_dir) 
            if f.endswith(".py") and not f.startswith("__") and f != "plugin_base.py"]

def load_specific_plugin(plugin_name):
    """Load only the specified plugin"""
    try:
        # Try relative import first (for development)
        try:
            module = importlib.import_module(f".plugins.{plugin_name}", package="src")
        except ImportError:
            # Fallback to absolute import (for installed package)
            module = importlib.import_module(f"src.plugins.{plugin_name}")
        return module.Plugin()
    except (ImportError, AttributeError) as e:
        raise ValueError(f"Could not load plugin '{plugin_name}': {e}")

def get_plugin_info() -> Dict[str, Any]:
    """Get plugin metadata with lightweight loading"""
    plugin_dir = os.path.join(os.path.dirname(__file__), "plugins")
    plugins_info = {}
    
    if not os.path.exists(plugin_dir):
        return plugins_info
    
    for file in os.listdir(plugin_dir):
        if file.endswith(".py") and not file.startswith("__") and file != "plugin_base.py":
            name = file[:-3]
            try:
                # Quick load to get metadata using same import logic
                try:
                    module = importlib.import_module(f".plugins.{name}", package="src")
                except ImportError:
                    module = importlib.import_module(f"src.plugins.{name}")
                plugin_instance = module.Plugin()
                
                if hasattr(plugin_instance, 'metadata'):
                    plugins_info[name] = {
                        'name': plugin_instance.metadata.name,
                        'description': plugin_instance.metadata.description,
                        'author': plugin_instance.metadata.author,
                        'version': plugin_instance.metadata.version,
                        'category': plugin_instance.metadata.category.value,
                        'requires_auth': plugin_instance.metadata.requires_auth,
                        'requires_connection': plugin_instance.metadata.requires_connection,
                        'external_dependencies': plugin_instance.metadata.external_dependencies,
                        'file': file,
                        'loaded': False
                    }
                else:
                    plugins_info[name] = {
                        'name': name,
                        'description': 'No description available',
                        'author': 'Unknown',
                        'version': '1.0.0',
                        'category': 'unknown',
                        'requires_auth': False,
                        'requires_connection': True,
                        'external_dependencies': [],
                        'file': file,
                        'loaded': False
                    }
            except Exception as e:
                plugins_info[name] = {
                    'name': name,
                    'description': f'Plugin load error: {e}',
                    'author': 'Unknown',
                    'version': '1.0.0',
                    'category': 'unknown',
                    'requires_auth': False,
                    'requires_connection': True,
                    'external_dependencies': [],
                    'file': file,
                    'loaded': False,
                    'error': str(e)
                }
    
    return plugins_info
