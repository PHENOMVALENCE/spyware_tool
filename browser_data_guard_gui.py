"""
Browser Data Guard – GUI
========================
One-click protection: blocks the simulator from reading Chrome/Edge passwords and history.
Close Chrome/Edge first, then click "Start protection". Click "Stop protection" when done.
"""

import sys
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

if sys.platform != "win32":
    print("Browser Data Guard only works on Windows.")
    sys.exit(1)

from browser_data_guard import acquire_locks, release_locks, is_browser_running


class GuardGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Browser Data Guard – Block Simulator")
        self.root.geometry("480x380")
        self.root.resizable(True, True)
        self.handles = []
        self.locked_paths = []

        # Main frame
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main, text="Browser Data Guard", font=("Segoe UI", 14, "bold")).pack(anchor=tk.W)
        ttk.Label(main, text="Blocks the simulator from reading Chrome/Edge saved passwords and history.", foreground="gray").pack(anchor=tk.W, pady=(0, 12))

        # Buttons
        btn_frame = ttk.Frame(main)
        btn_frame.pack(fill=tk.X, pady=(0, 8))

        self.start_btn = ttk.Button(btn_frame, text="Start protection", command=self.start_protection, width=18)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 8))

        self.stop_btn = ttk.Button(btn_frame, text="Stop protection", command=self.stop_protection, width=18, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)

        # Status
        ttk.Label(main, text="Status:", font=("Segoe UI", 9, "bold")).pack(anchor=tk.W, pady=(8, 2))
        self.status_text = scrolledtext.ScrolledText(main, height=12, wrap=tk.WORD, font=("Consolas", 9), state=tk.DISABLED)
        self.status_text.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        # Hint
        ttk.Label(main, text="Close Chrome and Edge before starting. For Edge, also end 'msedgewebview2.exe' in Task Manager if needed.", font=("Segoe UI", 8), foreground="gray", wraplength=440).pack(anchor=tk.W)

        self.set_status("Not protecting. Close browsers, then click Start protection.")

    def set_status(self, text):
        self.status_text.config(state=tk.NORMAL)
        self.status_text.delete(1.0, tk.END)
        self.status_text.insert(tk.END, text)
        self.status_text.config(state=tk.DISABLED)

    def start_protection(self):
        if is_browser_running():
            messagebox.showwarning(
                "Browser running",
                "Chrome or Edge is still running.\n\nClose the browser completely (check Task Manager), then click Start protection again."
            )
            return
        handles, locked_paths, status = acquire_locks(force=False)
        if not handles:
            self.set_status(status)
            messagebox.showwarning("Could not lock", status)
            return
        self.handles = handles
        self.locked_paths = locked_paths
        self.set_status(status)
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.root.title("Browser Data Guard – PROTECTING")
        messagebox.showinfo("Protection ON", "Simulator is now blocked.\n\nRun the simulator – it will fail to read passwords/history.\nClick Stop protection when you want to use the browser again.")

    def stop_protection(self):
        release_locks(self.handles)
        self.handles = []
        self.locked_paths = []
        self.set_status("Protection stopped. Browser files are released.\n\nYou can run the simulator again, or start protection again after closing browsers.")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.root.title("Browser Data Guard – Block Simulator")

    def on_closing(self):
        if self.handles:
            if messagebox.askyesno("Stop protection?", "Protection is active. Stop and close?"):
                release_locks(self.handles)
                self.handles = []
        self.root.destroy()


def main():
    root = tk.Tk()
    app = GuardGUI(root)
    root.protocol("WM_DELETE_WINDOW", app.on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()
