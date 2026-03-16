"""
auto_doc_generator.py

This tool generates documentation for a selected project directory using pdoc.
It:
  - Lets you choose a project folder via a file dialog.
  - Runs pdoc to generate HTML documentation into a local "docs" folder.
  - Opens the generated documentation in your web browser.

Make sure pdoc is installed (e.g., via pip install pdoc).
"""

import tkinter as tk
from tkinter import filedialog, messagebox
import subprocess
import webbrowser
import os

# Label for the toolbox button.
TOOL_NAME = "Automated Documentation Generator"

def run_tool():
    # Create a hidden Tkinter root for dialogs.
    root = tk.Tk()
    root.withdraw()
    
    # Ask the user to select the project directory.
    folder = filedialog.askdirectory(title="Select Project Directory")
    if not folder:
        return

    # Define the output directory for documentation.
    # This will generate the docs in a folder called "docs" in the current working directory.
    output_dir = os.path.join(os.getcwd(), "docs")
    
    try:
        # Run pdoc to generate HTML docs.
        # The command is modified to remove the unrecognized --html and --force flags.
        result = subprocess.run(
            ["pdoc", folder, "-o", output_dir],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            messagebox.showerror("Error", f"pdoc failed:\n{result.stderr}")
            return
    except Exception as e:
        messagebox.showerror("Error", f"Error running pdoc: {e}")
        return

    # Attempt to open the generated documentation.
    index_path = os.path.join(output_dir, "index.html")
    if os.path.exists(index_path):
        webbrowser.open(index_path)
    else:
        messagebox.showinfo("Documentation Generated", "Documentation generated, but index.html not found.")
    
    root.destroy()

if __name__ == '__main__':
    run_tool()
