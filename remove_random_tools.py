#!/usr/bin/env python3
"""
Remove random tools I created, keep only user's actual tools
"""
import os
import shutil

# Random tools I created (to remove)
random_tools = [
    "system_info_tool.py",
    "process_monitor.py", 
    "file_manager.py",
    "registry_cleaner.py",
    "password_generator.py"
]

# User's actual tools (to keep)
user_tools = [
    "code_formatter.py",
    "code_documentation.py",
    "NETWORK STABILITY MONITOR.py",
    "network_intelligence_engine.py",
    "network_intrusion_detector_pro.py",
    "folder_size_analyzer.py"
]

tools_dir = r"f:\DevCrow\Python\Automations\tools"

print("🗑️ Removing random tools I created...")

# Remove random tools
for tool in random_tools:
    tool_path = os.path.join(tools_dir, tool)
    if os.path.exists(tool_path):
        try:
            os.remove(tool_path)
            print(f"✅ Removed: {tool}")
        except Exception as e:
            print(f"❌ Failed to remove {tool}: {e}")
    else:
        print(f"⚠️ Tool not found: {tool}")

print("\n✅ Your actual tools are preserved:")
for tool in user_tools:
    tool_path = os.path.join(tools_dir, tool)
    if os.path.exists(tool_path):
        print(f"✅ {tool}")
    else:
        print(f"❌ Missing: {tool}")

print("\n🎉 Restored YOUR tools only!")
