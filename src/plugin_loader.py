import os
import importlib.util

def load_plugin():
    plugin_dir = os.path.join(os.path.dirname(__file__), "plugins")
    plugins = {}
    for file in os.listdir(plugin_dir):
        if file.endswith(".py") and not file.startswith("__"):
            name = file[:-3]
            module = __import__(f"src.plugins.{name}", fromlist=["Plugin"]) 
            plugins[name] = module.Plugin() # plugins class name should be 'Plugin'
    return plugins
