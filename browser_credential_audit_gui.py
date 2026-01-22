"""
Browser Credential Security Audit Tool - GUI Version
=====================================================

Graphical user interface for the browser credential audit tool.
Uses tkinter (built into Python) for cross-platform compatibility.

EDUCATIONAL USE ONLY - For Blue Team Training and Security Posture Assessment
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from datetime import datetime
import threading

# Import the audit functionality from the main script
from browser_credential_audit import BrowserCredentialAuditor


class CredentialAuditGUI:
    """
    Main GUI application for browser credential auditing.
    """
    
    def __init__(self, root):
        self.root = root
        self.root.title("Browser Credential Security Audit Tool")
        self.root.geometry("1000x700")
        self.root.resizable(True, True)
        
        # Variables
        self.selected_browser = tk.StringVar(value="Chrome")
        self.include_history = tk.BooleanVar(value=False)
        self.audit_running = False
        self.credentials = []
        self.history = []
        
        # Configure style
        self.setup_style()
        
        # Build UI
        self.create_widgets()
        
        # Center window
        self.center_window()
    
    def setup_style(self):
        """Configure ttk style for modern look."""
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure colors
        style.configure('Title.TLabel', font=('Arial', 14, 'bold'))
        style.configure('Heading.TLabel', font=('Arial', 10, 'bold'))
        style.configure('Status.TLabel', font=('Arial', 9))
    
    def center_window(self):
        """Center the window on screen."""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def create_widgets(self):
        """Create and layout all GUI widgets."""
        
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Title
        title_label = ttk.Label(
            main_frame,
            text="Browser Credential Security Audit Tool",
            style='Title.TLabel'
        )
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 10))
        
        # Subtitle
        subtitle_label = ttk.Label(
            main_frame,
            text="For Blue Team Training & Security Posture Assessment",
            font=('Arial', 9, 'italic'),
            foreground='gray'
        )
        subtitle_label.grid(row=1, column=0, columnspan=3, pady=(0, 20))
        
        # Left panel - Controls
        control_frame = ttk.LabelFrame(main_frame, text="Controls", padding="10")
        control_frame.grid(row=2, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), padx=(0, 10))
        
        # Browser selection
        ttk.Label(control_frame, text="Select Browser:", style='Heading.TLabel').grid(
            row=0, column=0, sticky=tk.W, pady=(0, 5)
        )
        
        browsers = ['Chrome', 'Edge', 'Brave', 'Opera', 'Vivaldi']
        browser_combo = ttk.Combobox(
            control_frame,
            textvariable=self.selected_browser,
            values=browsers,
            state='readonly',
            width=20
        )
        browser_combo.grid(row=1, column=0, sticky=tk.W, pady=(0, 15))
        
        # Include history checkbox
        history_check = ttk.Checkbutton(
            control_frame,
            text="Include Browser History",
            variable=self.include_history
        )
        history_check.grid(row=2, column=0, sticky=tk.W, pady=(0, 15))
        
        # Run audit button
        self.run_button = ttk.Button(
            control_frame,
            text="Run Audit",
            command=self.run_audit,
            width=20
        )
        self.run_button.grid(row=3, column=0, sticky=tk.W, pady=(0, 10))
        
        # Export button
        self.export_button = ttk.Button(
            control_frame,
            text="Export Results",
            command=self.export_results,
            width=20,
            state='disabled'
        )
        self.export_button.grid(row=4, column=0, sticky=tk.W, pady=(0, 10))
        
        # Clear button
        clear_button = ttk.Button(
            control_frame,
            text="Clear Results",
            command=self.clear_results,
            width=20
        )
        clear_button.grid(row=5, column=0, sticky=tk.W, pady=(0, 20))
        
        # Status section
        ttk.Label(control_frame, text="Status:", style='Heading.TLabel').grid(
            row=5, column=0, sticky=tk.W, pady=(0, 5)
        )
        
        self.status_label = ttk.Label(
            control_frame,
            text="Ready",
            style='Status.TLabel',
            foreground='green'
        )
        self.status_label.grid(row=7, column=0, sticky=tk.W, pady=(0, 10))
        
        # Progress bar
        self.progress = ttk.Progressbar(
            control_frame,
            mode='indeterminate',
            length=200
        )
        self.progress.grid(row=8, column=0, sticky=tk.W, pady=(0, 10))
        
        # Info section
        info_frame = ttk.LabelFrame(control_frame, text="Information", padding="10")
        info_frame.grid(row=9, column=0, sticky=(tk.W, tk.E), pady=(10, 0))
        
        info_text = """
⚠️ EDUCATIONAL USE ONLY

Requirements:
• Close browser before running
• Must run as same Windows user
• Windows OS required (DPAPI)

This tool demonstrates how
infostealer malware extracts
browser passwords for security
training purposes.
        """
        
        ttk.Label(
            info_frame,
            text=info_text,
            font=('Arial', 8),
            justify=tk.LEFT
        ).grid(row=0, column=0, sticky=tk.W)
        
        # Right panel - Results with Notebook (Tabs)
        results_notebook = ttk.Notebook(main_frame)
        results_notebook.grid(row=2, column=1, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Credentials Tab
        credentials_frame = ttk.Frame(results_notebook, padding="10")
        results_notebook.add(credentials_frame, text="Credentials")
        credentials_frame.columnconfigure(0, weight=1)
        credentials_frame.rowconfigure(0, weight=1)
        
        # History Tab
        history_frame = ttk.Frame(results_notebook, padding="10")
        results_notebook.add(history_frame, text="History")
        history_frame.columnconfigure(0, weight=1)
        history_frame.rowconfigure(0, weight=1)
        
        # Credentials Results
        results_frame = ttk.LabelFrame(credentials_frame, text="Credentials", padding="10")
        results_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(1, weight=1)
        
        # Credentials Results header
        cred_header_frame = ttk.Frame(results_frame)
        cred_header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.results_count_label = ttk.Label(
            cred_header_frame,
            text="No audit performed yet",
            style='Heading.TLabel'
        )
        self.results_count_label.grid(row=0, column=0, sticky=tk.W)
        
        # Credentials treeview (table)
        cred_tree_frame = ttk.Frame(results_frame)
        cred_tree_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        cred_tree_frame.columnconfigure(0, weight=1)
        cred_tree_frame.rowconfigure(0, weight=1)
        
        # Create credentials treeview with scrollbars
        cred_scrollbar_y = ttk.Scrollbar(cred_tree_frame, orient=tk.VERTICAL)
        cred_scrollbar_x = ttk.Scrollbar(cred_tree_frame, orient=tk.HORIZONTAL)
        
        self.tree = ttk.Treeview(
            cred_tree_frame,
            columns=('URL', 'Username', 'Password', 'Last Used', 'Times Used'),
            show='headings',
            yscrollcommand=cred_scrollbar_y.set,
            xscrollcommand=cred_scrollbar_x.set,
            selectmode='extended'
        )
        
        # Configure columns
        self.tree.heading('URL', text='URL')
        self.tree.heading('Username', text='Username')
        self.tree.heading('Password', text='Password')
        self.tree.heading('Last Used', text='Last Used')
        self.tree.heading('Times Used', text='Times Used')
        
        self.tree.column('URL', width=300, anchor=tk.W)
        self.tree.column('Username', width=200, anchor=tk.W)
        self.tree.column('Password', width=200, anchor=tk.W)
        self.tree.column('Last Used', width=150, anchor=tk.W)
        self.tree.column('Times Used', width=100, anchor=tk.CENTER)
        
        cred_scrollbar_y.config(command=self.tree.yview)
        cred_scrollbar_x.config(command=self.tree.xview)
        
        self.tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        cred_scrollbar_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        cred_scrollbar_x.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # History Results
        history_results_frame = ttk.LabelFrame(history_frame, text="Browser History", padding="10")
        history_results_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        history_results_frame.columnconfigure(0, weight=1)
        history_results_frame.rowconfigure(1, weight=1)
        
        # History Results header
        hist_header_frame = ttk.Frame(history_results_frame)
        hist_header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        
        self.history_count_label = ttk.Label(
            hist_header_frame,
            text="No history extracted yet",
            style='Heading.TLabel'
        )
        self.history_count_label.grid(row=0, column=0, sticky=tk.W)
        
        # History treeview (table)
        hist_tree_frame = ttk.Frame(history_results_frame)
        hist_tree_frame.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        hist_tree_frame.columnconfigure(0, weight=1)
        hist_tree_frame.rowconfigure(0, weight=1)
        
        # Create history treeview with scrollbars
        hist_scrollbar_y = ttk.Scrollbar(hist_tree_frame, orient=tk.VERTICAL)
        hist_scrollbar_x = ttk.Scrollbar(hist_tree_frame, orient=tk.HORIZONTAL)
        
        self.history_tree = ttk.Treeview(
            hist_tree_frame,
            columns=('URL', 'Title', 'Visit Count', 'Last Visit', 'Transition'),
            show='headings',
            yscrollcommand=hist_scrollbar_y.set,
            xscrollcommand=hist_scrollbar_x.set,
            selectmode='extended'
        )
        
        # Configure history columns
        self.history_tree.heading('URL', text='URL')
        self.history_tree.heading('Title', text='Title')
        self.history_tree.heading('Visit Count', text='Visit Count')
        self.history_tree.heading('Last Visit', text='Last Visit')
        self.history_tree.heading('Transition', text='Type')
        
        self.history_tree.column('URL', width=400, anchor=tk.W)
        self.history_tree.column('Title', width=300, anchor=tk.W)
        self.history_tree.column('Visit Count', width=100, anchor=tk.CENTER)
        self.history_tree.column('Last Visit', width=150, anchor=tk.W)
        self.history_tree.column('Transition', width=120, anchor=tk.W)
        
        hist_scrollbar_y.config(command=self.history_tree.yview)
        hist_scrollbar_x.config(command=self.history_tree.xview)
        
        self.history_tree.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        hist_scrollbar_y.grid(row=0, column=1, sticky=(tk.N, tk.S))
        hist_scrollbar_x.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        # Log/Status text area
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding="10")
        log_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(10, 0))
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=8,
            wrap=tk.WORD,
            font=('Consolas', 9)
        )
        self.log_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.log_text.config(state='disabled')
        
        # Initial log message
        self.log("Application started. Ready to perform audit.")
        self.log("⚠️ EDUCATIONAL USE ONLY - For security training purposes")
    
    def log(self, message, level='INFO'):
        """Add message to log area."""
        self.log_text.config(state='normal')
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color coding
        if level == 'ERROR':
            prefix = f"[{timestamp}] [ERROR] "
            color = 'red'
        elif level == 'SUCCESS':
            prefix = f"[{timestamp}] [SUCCESS] "
            color = 'green'
        elif level == 'WARNING':
            prefix = f"[{timestamp}] [WARNING] "
            color = 'orange'
        else:
            prefix = f"[{timestamp}] [INFO] "
            color = 'black'
        
        self.log_text.insert(tk.END, prefix + message + "\n")
        self.log_text.see(tk.END)
        self.log_text.config(state='disabled')
    
    def update_status(self, message, color='black'):
        """Update status label."""
        self.status_label.config(text=message, foreground=color)
        self.root.update_idletasks()
    
    def run_audit(self):
        """Run the credential audit in a separate thread."""
        if self.audit_running:
            messagebox.showwarning("Audit Running", "An audit is already in progress.")
            return
        
        browser = self.selected_browser.get()
        include_hist = self.include_history.get()
        
        history_text = "\n• Include browser history" if include_hist else ""
        
        # Confirm before running
        response = messagebox.askyesno(
            "Confirm Audit",
            f"Are you ready to audit {browser}?\n\n"
            "⚠️ Make sure:\n"
            "• Browser is completely closed\n"
            "• You're running as the correct Windows user{history_text}\n\n"
            "Continue?",
            icon='warning'
        )
        
        if not response:
            return
        
        # Clear previous results
        self.clear_tree()
        
        # Start audit in thread
        self.audit_running = True
        self.run_button.config(state='disabled')
        self.export_button.config(state='disabled')
        self.progress.start()
        self.update_status("Running audit...", 'blue')
        
        thread = threading.Thread(target=self._perform_audit, args=(browser, include_hist), daemon=True)
        thread.start()
    
    def _perform_audit(self, browser_name, include_history):
        """Perform the actual audit (runs in thread)."""
        try:
            self.log(f"Starting audit for {browser_name}...")
            self.log("Step 1: Initializing auditor...")
            
            # Initialize auditor
            auditor = BrowserCredentialAuditor(browser_name=browser_name)
            
            self.log("Step 2: Extracting master key from Local State...")
            auditor.master_key = auditor._get_master_key()
            self.log("✓ Master key extracted and decrypted")
            
            self.log("Step 3: Extracting credentials from Login Data...")
            credentials = auditor._extract_credentials()
            self.log(f"✓ Found {len(credentials)} saved credentials")
            
            history = []
            if include_history:
                self.log("Step 4: Extracting browser history...")
                try:
                    history = auditor._extract_history()
                    self.log(f"✓ Found {len(history)} history entries")
                except Exception as e:
                    self.log(f"⚠ History extraction failed: {str(e)}", 'WARNING')
                    history = []
            
            # Update UI in main thread
            self.root.after(0, self._audit_complete, credentials, history, None)
            
        except FileNotFoundError as e:
            error_msg = str(e)
            self.log(f"File not found: {error_msg}", 'ERROR')
            self.root.after(0, self._audit_complete, [], [], error_msg)
            
        except PermissionError as e:
            error_msg = str(e)
            self.log(f"Permission error: {error_msg}", 'ERROR')
            self.log("Make sure the browser is closed!", 'WARNING')
            self.root.after(0, self._audit_complete, [], [], error_msg)
            
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)}"
            self.log(error_msg, 'ERROR')
            self.root.after(0, self._audit_complete, [], [], error_msg)
    
    def _audit_complete(self, credentials, history, error):
        """Handle audit completion (called from main thread)."""
        self.audit_running = False
        self.progress.stop()
        self.run_button.config(state='normal')
        
        if error:
            self.update_status("Audit failed", 'red')
            messagebox.showerror("Audit Failed", error)
            self.log("Audit failed. See log for details.", 'ERROR')
        else:
            self.credentials = credentials
            self.history = history
            
            status_msg = f"Audit complete - {len(credentials)} credentials"
            if history:
                status_msg += f", {len(history)} history entries"
            self.update_status(status_msg, 'green')
            
            self.log(f"Audit completed successfully. Found {len(credentials)} credentials.", 'SUCCESS')
            if history:
                self.log(f"Found {len(history)} history entries.", 'SUCCESS')
            
            if credentials:
                self.populate_tree(credentials)
                self.export_button.config(state='normal')
                
                msg = f"Successfully extracted {len(credentials)} credentials."
                if history:
                    msg += f"\nExtracted {len(history)} history entries."
                msg += "\n\n⚠️ This demonstrates what spyware would see."
                
                messagebox.showinfo("Audit Complete", msg)
            else:
                self.log("No credentials found in browser.", 'WARNING')
                messagebox.showinfo(
                    "No Credentials",
                    "No saved passwords found in the browser.\n\n"
                    "This could mean:\n"
                    "• No passwords are saved\n"
                    "• Using a different browser profile\n"
                    "• Browser data is stored elsewhere"
                )
            
            # Populate history if available
            if history:
                self.populate_history_tree(history)
    
    def populate_tree(self, credentials):
        """Populate the results treeview with credentials."""
        self.clear_tree()
        
        for cred in credentials:
            url = cred['url'] or '[No URL]'
            username = cred['username'] or '[No Username]'
            password = cred['password'] or '[No Password]'
            
            # Format dates
            if cred['last_used']:
                last_used = cred['last_used'].strftime('%Y-%m-%d %H:%M')
            else:
                last_used = 'Never'
            
            times_used = str(cred['times_used'] or 0)
            
            # Insert into tree
            self.tree.insert('', tk.END, values=(
                url[:80] + '...' if len(url) > 80 else url,
                username[:50] + '...' if len(username) > 50 else username,
                password[:50] + '...' if len(password) > 50 else password,
                last_used,
                times_used
            ))
        
        # Update count label
        self.results_count_label.config(
            text=f"Found {len(credentials)} credential(s)"
        )
    
    def populate_history_tree(self, history_entries):
        """Populate the history treeview with history entries."""
        # Clear existing entries
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        
        for entry in history_entries:
            url = entry['url'] or '[No URL]'
            title = entry['title'] or '[No Title]'
            visit_count = str(entry['visit_count'] or 0)
            
            if entry['last_visit']:
                last_visit = entry['last_visit'].strftime('%Y-%m-%d %H:%M')
            else:
                last_visit = 'Unknown'
            
            transition = entry.get('transition', 'Unknown')
            
            # Insert into tree
            self.history_tree.insert('', tk.END, values=(
                url[:100] + '...' if len(url) > 100 else url,
                title[:80] + '...' if len(title) > 80 else title,
                visit_count,
                last_visit,
                transition
            ))
        
        # Update count label
        self.history_count_label.config(
            text=f"Found {len(history_entries)} history entries"
        )
    
    def clear_tree(self):
        """Clear all items from the treeviews."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.results_count_label.config(text="No results")
        
        for item in self.history_tree.get_children():
            self.history_tree.delete(item)
        self.history_count_label.config(text="No history extracted yet")
    
    def clear_results(self):
        """Clear all results and log."""
        self.clear_tree()
        self.credentials = []
        self.history = []
        self.export_button.config(state='disabled')
        self.log_text.config(state='normal')
        self.log_text.delete(1.0, tk.END)
        self.log_text.config(state='disabled')
        self.log("Results cleared. Ready for new audit.")
        self.update_status("Ready", 'green')
    
    def export_results(self):
        """Export results to a text file."""
        if not self.credentials:
            messagebox.showwarning("No Results", "No credentials to export.")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("CSV files", "*.csv"),
                ("All files", "*.*")
            ],
            title="Export Credentials"
        )
        
        if not filename:
            return
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write("=" * 100 + "\n")
                f.write("Browser Credential Audit Results\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("=" * 100 + "\n\n")
                
                f.write(f"{'URL':<50} | {'Username':<30} | {'Password':<25} | {'Last Used':<20} | {'Times Used':<10}\n")
                f.write("-" * 100 + "\n")
                
                for cred in self.credentials:
                    url = cred['url'] or '[No URL]'
                    username = cred['username'] or '[No Username]'
                    password = cred['password'] or '[No Password]'
                    
                    if cred['last_used']:
                        last_used = cred['last_used'].strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        last_used = 'Never'
                    
                    times_used = str(cred['times_used'] or 0)
                    
                    f.write(f"{url[:47]:<50} | {username[:27]:<30} | {password[:22]:<25} | {last_used:<20} | {times_used:<10}\n")
                
                f.write("\n" + "=" * 100 + "\n")
                f.write(f"Total Credentials: {len(self.credentials)}\n")
                f.write("=" * 100 + "\n")
                
                # Export history if available
                if self.history:
                    f.write("\n\n" + "=" * 100 + "\n")
                    f.write("BROWSER HISTORY\n")
                    f.write("=" * 100 + "\n\n")
                    
                    f.write(f"{'URL':<60} | {'Title':<40} | {'Visit Count':<12} | {'Last Visit':<20} | {'Type':<15}\n")
                    f.write("-" * 100 + "\n")
                    
                    for entry in self.history:
                        url = entry['url'] or '[No URL]'
                        title = entry['title'] or '[No Title]'
                        visit_count = str(entry['visit_count'] or 0)
                        
                        if entry['last_visit']:
                            last_visit = entry['last_visit'].strftime('%Y-%m-%d %H:%M:%S')
                        else:
                            last_visit = 'Unknown'
                        
                        transition = entry.get('transition', 'Unknown')
                        
                        f.write(f"{url[:57]:<60} | {title[:37]:<40} | {visit_count:<12} | {last_visit:<20} | {transition:<15}\n")
                    
                    f.write("\n" + "=" * 100 + "\n")
                    f.write(f"Total History Entries: {len(self.history)}\n")
                    f.write("=" * 100 + "\n")
            
            self.log(f"Results exported to: {filename}", 'SUCCESS')
            messagebox.showinfo("Export Complete", f"Results exported to:\n{filename}")
            
        except Exception as e:
            error_msg = f"Failed to export: {str(e)}"
            self.log(error_msg, 'ERROR')
            messagebox.showerror("Export Failed", error_msg)


def main():
    """Main entry point for GUI application."""
    root = tk.Tk()
    app = CredentialAuditGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
