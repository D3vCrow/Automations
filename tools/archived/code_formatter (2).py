"""
code_formatter_linter.py

This tool helps keep your code style and quality in check by running:
  - Black: an automatic code formatter.
  - flake8: a popular linter to catch potential issues.

It uses a file dialog to let you choose the project directory, runs the commands via subprocess,
and displays the output in a Tkinter window.
"""

import tkinter as tk
from tkinter import messagebox, filedialog
import subprocess

# Label for the toolbox button.
TOOL_NAME = "Code Formatter & Linter Runner"


def run_tool():
    # Create a hidden Tkinter root for dialogs.
    root = tk.Tk()
    root.withdraw()

    # Ask the user to select the project folder.
    folder = filedialog.askdirectory(title="Select Project Directory")
    if not folder:
        return

    # Run the Black formatter.
    try:
        result_black = subprocess.run(["black", folder], capture_output=True, text=True)
        # Combine standard output and errors.
        black_output = result_black.stdout + "\n" + result_black.stderr
    except Exception as e:
        black_output = f"Error running Black: {e}"

    # Run the flake8 linter.
    try:
        result_flake8 = subprocess.run(
            ["flake8", folder], capture_output=True, text=True
        )
        flake8_output = result_flake8.stdout + "\n" + result_flake8.stderr
    except Exception as e:
        flake8_output = f"Error running flake8: {e}"

    # Combine outputs.
    output = (
        "=== Black Formatter Output ===\n"
        + black_output
        + "\n\n=== flake8 Linter Output ===\n"
        + flake8_output
    )

    # Create a new window to display the results.
    result_win = tk.Toplevel()
    result_win.title("Formatter & Linter Results")

    text_widget = tk.Text(result_win, wrap="word", width=80, height=20)
    text_widget.insert("1.0", output)
    text_widget.config(state="disabled")  # Make the text read-only.
    text_widget.pack(padx=10, pady=10)

    root.mainloop()


if __name__ == "__main__":
    run_tool()
