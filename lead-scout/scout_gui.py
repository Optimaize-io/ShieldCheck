#!/usr/bin/env python3
"""
Lead Scout GUI - NIS2 OSINT Scanner
Graphical interface for the Lead Scout scanning tool.
"""

import os
import sys
import json
import logging
import threading
import webbrowser
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from pathlib import Path
from datetime import datetime
from typing import List, Optional

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from scout import LeadScout, CompanyInput, load_csv, load_json
from scoring.scorer import LeadScore, LeadTier


class LogHandler(logging.Handler):
    """Routes log messages to a tkinter Text widget."""

    def __init__(self, text_widget: scrolledtext.ScrolledText):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record) + "\n"
        try:
            self.text_widget.after(0, self._append, msg)
        except Exception:
            pass

    def _append(self, msg: str):
        self.text_widget.configure(state="normal")
        self.text_widget.insert(tk.END, msg)
        self.text_widget.see(tk.END)
        self.text_widget.configure(state="disabled")


class CompanyInputDialog(tk.Toplevel):
    """Dialog for adding a single company."""

    def __init__(self, parent):
        super().__init__(parent)
        self.title("Add Company")
        self.resizable(False, False)
        self.result: Optional[CompanyInput] = None

        self.transient(parent)
        self.grab_set()

        frame = ttk.Frame(self, padding=15)
        frame.pack(fill=tk.BOTH, expand=True)

        labels = ["Company Name:", "Domain:", "Sector:", "Employees:"]
        self.entries = {}
        defaults = {"Sector:": "Unknown", "Employees:": "100"}

        for i, label in enumerate(labels):
            ttk.Label(frame, text=label).grid(row=i, column=0, sticky=tk.W, pady=3)
            entry = ttk.Entry(frame, width=35)
            entry.grid(row=i, column=1, sticky=tk.EW, pady=3, padx=(8, 0))
            if label in defaults:
                entry.insert(0, defaults[label])
            self.entries[label] = entry

        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=len(labels), column=0, columnspan=2, pady=(12, 0))
        ttk.Button(btn_frame, text="Add", command=self._on_add).pack(
            side=tk.LEFT, padx=4
        )
        ttk.Button(btn_frame, text="Cancel", command=self.destroy).pack(
            side=tk.LEFT, padx=4
        )

        self.entries["Company Name:"].focus_set()
        self.bind("<Return>", lambda e: self._on_add())
        self.bind("<Escape>", lambda e: self.destroy())

        # Center on parent
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")

    def _on_add(self):
        name = self.entries["Company Name:"].get().strip()
        domain = self.entries["Domain:"].get().strip()
        sector = self.entries["Sector:"].get().strip() or "Unknown"
        emp_str = self.entries["Employees:"].get().strip()

        if not name:
            messagebox.showwarning(
                "Validation", "Company name is required.", parent=self
            )
            return
        if not domain:
            messagebox.showwarning("Validation", "Domain is required.", parent=self)
            return

        try:
            employees = int(emp_str) if emp_str else 100
        except ValueError:
            messagebox.showwarning(
                "Validation", "Employees must be a number.", parent=self
            )
            return

        domain = domain.replace("https://", "").replace("http://", "").rstrip("/")

        self.result = CompanyInput(
            name=name, domain=domain, sector=sector, employees=employees
        )
        self.destroy()


class DetailWindow(tk.Toplevel):
    """Window showing detailed scan results for a single company."""

    def __init__(self, parent, lead_dict: dict):
        super().__init__(parent)
        self.title(f"Details - {lead_dict['company_name']}")
        self.geometry("720x600")
        self.minsize(500, 400)

        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        # --- Overview tab ---
        overview = ttk.Frame(notebook, padding=10)
        notebook.add(overview, text="Overview")

        info_items = [
            ("Company", lead_dict["company_name"]),
            ("Domain", lead_dict["domain"]),
            ("Sector", lead_dict["sector"]),
            ("Employees", str(lead_dict["employees"])),
            ("Tier", lead_dict["tier"]),
            ("Score", f"{lead_dict['total_score']:.1f} / {lead_dict['max_score']:.0f}"),
            ("Findings", str(lead_dict["findings_count"])),
        ]
        nis2 = lead_dict.get("nis2", {})
        if nis2:
            info_items.append(("NIS2 Covered", "Yes" if nis2.get("covered") else "No"))
            if nis2.get("sector"):
                info_items.append(("NIS2 Sector", nis2["sector"]))
            info_items.append(
                ("Compliance Priority", nis2.get("compliance_priority", "N/A"))
            )

        for i, (label, value) in enumerate(info_items):
            ttk.Label(overview, text=f"{label}:", font=("Segoe UI", 10, "bold")).grid(
                row=i, column=0, sticky=tk.W, pady=2
            )
            ttk.Label(overview, text=value, font=("Segoe UI", 10)).grid(
                row=i, column=1, sticky=tk.W, pady=2, padx=(10, 0)
            )

        if lead_dict.get("management_summary"):
            ttk.Separator(overview, orient=tk.HORIZONTAL).grid(
                row=len(info_items), column=0, columnspan=2, sticky=tk.EW, pady=8
            )
            ttk.Label(
                overview, text="Management Summary:", font=("Segoe UI", 10, "bold")
            ).grid(row=len(info_items) + 1, column=0, columnspan=2, sticky=tk.W)
            summary_text = tk.Text(
                overview, wrap=tk.WORD, height=5, font=("Segoe UI", 9)
            )
            summary_text.grid(
                row=len(info_items) + 2, column=0, columnspan=2, sticky=tk.NSEW, pady=4
            )
            summary_text.insert("1.0", lead_dict["management_summary"])
            summary_text.configure(state="disabled")
            overview.grid_rowconfigure(len(info_items) + 2, weight=1)
            overview.grid_columnconfigure(1, weight=1)

        # --- Scores tab ---
        scores_frame = ttk.Frame(notebook, padding=10)
        notebook.add(scores_frame, text="Scores")

        scores = lead_dict.get("scores", {})
        score_tree = ttk.Treeview(
            scores_frame, columns=("score", "desc"), show="headings", height=12
        )
        score_tree.heading("score", text="Score")
        score_tree.heading("desc", text="Description")
        score_tree.column("score", width=60, anchor=tk.CENTER)
        score_tree.column("desc", width=500)
        score_tree.pack(fill=tk.BOTH, expand=True)

        dimension_labels = {
            "email_security": "Email Security",
            "technical_hygiene": "Technical Hygiene",
            "tls_certificate": "TLS Certificate",
            "http_headers": "HTTP Headers",
            "cookie_compliance": "Cookie Compliance",
            "attack_surface": "Attack Surface",
            "tech_stack": "Tech Stack",
            "admin_panel": "Admin Panel",
            "security_hiring": "Security Hiring",
            "security_governance": "Security Governance",
            "security_communication": "Security Communication",
            "nis2_readiness": "NIS2 Readiness",
        }
        for key, label in dimension_labels.items():
            s = scores.get(key, {})
            score_val = s.get("score", "?")
            desc = s.get("description", "")
            emoji = "🔴" if score_val == 0 else ("🟡" if score_val == 1 else "🟢")
            score_tree.insert(
                "", tk.END, text=label, values=(f"{emoji} {score_val}/2", desc)
            )

        # --- Gaps tab ---
        gaps_frame = ttk.Frame(notebook, padding=10)
        notebook.add(gaps_frame, text="Key Gaps")

        gaps_text = scrolledtext.ScrolledText(
            gaps_frame, wrap=tk.WORD, font=("Segoe UI", 9)
        )
        gaps_text.pack(fill=tk.BOTH, expand=True)

        for gap in lead_dict.get("key_gaps", []):
            gaps_text.insert(tk.END, f"• {gap}\n\n")

        if lead_dict.get("key_gaps_detailed"):
            gaps_text.insert(tk.END, "\n--- Detailed Gaps ---\n\n")
            for g in lead_dict["key_gaps_detailed"]:
                if isinstance(g, dict):
                    gaps_text.insert(
                        tk.END, f"[{g.get('category', '')}] {g.get('title', '')}\n"
                    )
                    gaps_text.insert(tk.END, f"  {g.get('description', '')}\n\n")
                else:
                    gaps_text.insert(tk.END, f"• {g}\n\n")
        gaps_text.configure(state="disabled")

        # --- Positives tab ---
        pos_frame = ttk.Frame(notebook, padding=10)
        notebook.add(pos_frame, text="Positive Findings")

        pos_text = scrolledtext.ScrolledText(
            pos_frame, wrap=tk.WORD, font=("Segoe UI", 9)
        )
        pos_text.pack(fill=tk.BOTH, expand=True)
        for p in lead_dict.get("positive_findings", []):
            pos_text.insert(tk.END, f"✓ {p}\n\n")
        pos_text.configure(state="disabled")

        # --- Sales tab ---
        sales_frame = ttk.Frame(notebook, padding=10)
        notebook.add(sales_frame, text="Sales Angles")

        sales_text = scrolledtext.ScrolledText(
            sales_frame, wrap=tk.WORD, font=("Segoe UI", 9)
        )
        sales_text.pack(fill=tk.BOTH, expand=True)
        for s in lead_dict.get("sales_angles", []):
            sales_text.insert(tk.END, f"→ {s}\n\n")
        sales_text.configure(state="disabled")

        # Center on parent
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")


class LeadScoutGUI:
    """Main GUI application for Lead Scout."""

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("Lead Scout - NIS2 OSINT Scanner")
        self.root.geometry("1000x720")
        self.root.minsize(800, 600)

        self.companies: List[CompanyInput] = []
        self.results: List[LeadScore] = []
        self.results_dicts: List[dict] = []
        self.scanning = False
        self.scan_thread: Optional[threading.Thread] = None

        self._build_ui()
        self._setup_logging()

    # ── UI Construction ──────────────────────────────────────────

    def _build_ui(self):
        style = ttk.Style()
        style.theme_use("clam" if sys.platform != "win32" else "vista")

        # Menu bar
        menubar = tk.Menu(self.root)
        file_menu = tk.Menu(menubar, tearoff=0)
        file_menu.add_command(
            label="Load CSV/JSON...", command=self._load_file, accelerator="Ctrl+O"
        )
        file_menu.add_command(
            label="Add Company...", command=self._add_company, accelerator="Ctrl+N"
        )
        file_menu.add_separator()
        file_menu.add_command(label="Export Results JSON...", command=self._export_json)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        menubar.add_cascade(label="File", menu=file_menu)

        report_menu = tk.Menu(menubar, tearoff=0)
        report_menu.add_command(
            label="Open HTML Report", command=self._open_html_report
        )
        report_menu.add_command(
            label="Open Report Folder", command=self._open_output_folder
        )
        menubar.add_cascade(label="Reports", menu=report_menu)

        self.root.config(menu=menubar)
        self.root.bind("<Control-o>", lambda e: self._load_file())
        self.root.bind("<Control-n>", lambda e: self._add_company())

        # Main paned window
        paned = ttk.PanedWindow(self.root, orient=tk.VERTICAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        # ── Top section: input + controls ──
        top_frame = ttk.Frame(paned)
        paned.add(top_frame, weight=3)

        # Controls bar
        ctrl = ttk.LabelFrame(top_frame, text="Scan Controls", padding=8)
        ctrl.pack(fill=tk.X, pady=(0, 4))

        ttk.Button(ctrl, text="Load File", command=self._load_file).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(ctrl, text="Add Company", command=self._add_company).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(ctrl, text="Remove Selected", command=self._remove_selected).pack(
            side=tk.LEFT, padx=2
        )
        ttk.Button(ctrl, text="Clear All", command=self._clear_companies).pack(
            side=tk.LEFT, padx=2
        )

        ttk.Separator(ctrl, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=8)

        ttk.Label(ctrl, text="Timeout:").pack(side=tk.LEFT, padx=(0, 2))
        self.timeout_var = tk.StringVar(value="8")
        ttk.Spinbox(ctrl, from_=1, to=60, width=4, textvariable=self.timeout_var).pack(
            side=tk.LEFT
        )
        ttk.Label(ctrl, text="s").pack(side=tk.LEFT, padx=(0, 8))

        ttk.Label(ctrl, text="Delay:").pack(side=tk.LEFT, padx=(0, 2))
        self.delay_var = tk.StringVar(value="1")
        ttk.Spinbox(ctrl, from_=0, to=30, width=4, textvariable=self.delay_var).pack(
            side=tk.LEFT
        )
        ttk.Label(ctrl, text="s").pack(side=tk.LEFT, padx=(0, 8))

        self.verbose_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(ctrl, text="Verbose", variable=self.verbose_var).pack(
            side=tk.LEFT, padx=4
        )

        ttk.Separator(ctrl, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=8)

        self.scan_btn = ttk.Button(ctrl, text="▶ Start Scan", command=self._start_scan)
        self.scan_btn.pack(side=tk.LEFT, padx=4)
        self.stop_btn = ttk.Button(
            ctrl, text="■ Stop", command=self._stop_scan, state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=2)

        # Company input list
        input_frame = ttk.LabelFrame(top_frame, text="Companies to Scan", padding=4)
        input_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 4))

        cols_input = ("name", "domain", "sector", "employees")
        self.input_tree = ttk.Treeview(
            input_frame, columns=cols_input, show="headings", height=5
        )
        self.input_tree.heading("name", text="Company Name")
        self.input_tree.heading("domain", text="Domain")
        self.input_tree.heading("sector", text="Sector")
        self.input_tree.heading("employees", text="Employees")
        self.input_tree.column("name", width=200)
        self.input_tree.column("domain", width=200)
        self.input_tree.column("sector", width=150)
        self.input_tree.column("employees", width=80, anchor=tk.CENTER)

        scroll_input = ttk.Scrollbar(
            input_frame, orient=tk.VERTICAL, command=self.input_tree.yview
        )
        self.input_tree.configure(yscrollcommand=scroll_input.set)
        self.input_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll_input.pack(side=tk.RIGHT, fill=tk.Y)

        # Results table
        results_frame = ttk.LabelFrame(top_frame, text="Scan Results", padding=4)
        results_frame.pack(fill=tk.BOTH, expand=True)

        cols_result = ("tier", "name", "domain", "score", "findings", "sector")
        self.result_tree = ttk.Treeview(
            results_frame, columns=cols_result, show="headings", height=6
        )
        self.result_tree.heading("tier", text="Tier")
        self.result_tree.heading("name", text="Company")
        self.result_tree.heading("domain", text="Domain")
        self.result_tree.heading("score", text="Score")
        self.result_tree.heading("findings", text="Findings")
        self.result_tree.heading("sector", text="Sector")
        self.result_tree.column("tier", width=80, anchor=tk.CENTER)
        self.result_tree.column("name", width=180)
        self.result_tree.column("domain", width=180)
        self.result_tree.column("score", width=80, anchor=tk.CENTER)
        self.result_tree.column("findings", width=70, anchor=tk.CENTER)
        self.result_tree.column("sector", width=140)
        self.result_tree.bind("<Double-1>", self._on_result_double_click)

        scroll_result = ttk.Scrollbar(
            results_frame, orient=tk.VERTICAL, command=self.result_tree.yview
        )
        self.result_tree.configure(yscrollcommand=scroll_result.set)
        self.result_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll_result.pack(side=tk.RIGHT, fill=tk.Y)

        # ── Bottom section: log output ──
        log_frame = ttk.LabelFrame(paned, text="Scan Log", padding=4)
        paned.add(log_frame, weight=1)

        self.log_text = scrolledtext.ScrolledText(
            log_frame, state="disabled", font=("Consolas", 9), height=8
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Status bar
        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(
            self.root,
            textvariable=self.status_var,
            relief=tk.SUNKEN,
            anchor=tk.W,
            padding=2,
        )
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

        # Progress bar
        self.progress = ttk.Progressbar(self.root, mode="determinate")
        self.progress.pack(fill=tk.X, side=tk.BOTTOM, padx=6, pady=2)

    def _setup_logging(self):
        handler = LogHandler(self.log_text)
        handler.setLevel(logging.INFO)
        handler.setFormatter(
            logging.Formatter(
                "%(asctime)s - %(levelname)s - %(message)s", datefmt="%H:%M:%S"
            )
        )
        logging.getLogger().addHandler(handler)

    # ── Company management ───────────────────────────────────────

    def _load_file(self):
        filepath = filedialog.askopenfilename(
            title="Select Companies File",
            filetypes=[
                ("CSV files", "*.csv"),
                ("JSON files", "*.json"),
                ("All files", "*.*"),
            ],
        )
        if not filepath:
            return

        try:
            if filepath.lower().endswith(".json"):
                loaded = load_json(filepath)
            else:
                loaded = load_csv(filepath)

            if not loaded:
                messagebox.showwarning("Load File", "No valid companies found in file.")
                return

            self.companies.extend(loaded)
            self._refresh_input_tree()
            self.status_var.set(
                f"Loaded {len(loaded)} companies from {Path(filepath).name}"
            )
        except Exception as e:
            messagebox.showerror("Load Error", str(e))

    def _add_company(self):
        dialog = CompanyInputDialog(self.root)
        self.root.wait_window(dialog)
        if dialog.result:
            self.companies.append(dialog.result)
            self._refresh_input_tree()
            self.status_var.set(f"Added {dialog.result.name}")

    def _remove_selected(self):
        selected = self.input_tree.selection()
        if not selected:
            return
        indices = sorted(
            [self.input_tree.index(item) for item in selected], reverse=True
        )
        for idx in indices:
            if 0 <= idx < len(self.companies):
                del self.companies[idx]
        self._refresh_input_tree()

    def _clear_companies(self):
        self.companies.clear()
        self._refresh_input_tree()
        self.status_var.set("Cleared all companies")

    def _refresh_input_tree(self):
        self.input_tree.delete(*self.input_tree.get_children())
        for c in self.companies:
            self.input_tree.insert(
                "", tk.END, values=(c.name, c.domain, c.sector, c.employees)
            )

    # ── Scanning ─────────────────────────────────────────────────

    def _start_scan(self):
        if not self.companies:
            messagebox.showinfo("No Companies", "Load a file or add companies first.")
            return

        if self.scanning:
            return

        self.scanning = True
        self.scan_btn.configure(state=tk.DISABLED)
        self.stop_btn.configure(state=tk.NORMAL)
        self.results.clear()
        self.results_dicts.clear()
        self.result_tree.delete(*self.result_tree.get_children())

        self.progress["maximum"] = len(self.companies)
        self.progress["value"] = 0

        # Clear log
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", tk.END)
        self.log_text.configure(state="disabled")

        timeout = float(self.timeout_var.get())
        delay = float(self.delay_var.get())
        verbose = self.verbose_var.get()

        self._stop_event = threading.Event()

        self.scan_thread = threading.Thread(
            target=self._scan_worker,
            args=(list(self.companies), timeout, delay, verbose),
            daemon=True,
        )
        self.scan_thread.start()
        self.status_var.set("Scanning...")

    def _stop_scan(self):
        if self.scanning:
            self._stop_event.set()
            self.status_var.set("Stopping after current company...")

    def _scan_worker(
        self, companies: List[CompanyInput], timeout: float, delay: float, verbose: bool
    ):
        """Background worker that runs the scan."""
        import time

        try:
            scout = LeadScout(timeout=timeout, verbose=verbose)
            total = len(companies)

            for i, company in enumerate(companies):
                if self._stop_event.is_set():
                    self.root.after(0, self._log_msg, "Scan stopped by user.")
                    break

                self.root.after(
                    0,
                    self._update_status,
                    f"Scanning {i + 1}/{total}: {company.name}...",
                )

                try:
                    result = scout.scan_company(company)
                    result_dict = result.to_dict()
                    self.results.append(result)
                    self.results_dicts.append(result_dict)
                    self.root.after(0, self._add_result_row, result_dict)
                except Exception as e:
                    self.root.after(
                        0, self._log_msg, f"ERROR scanning {company.name}: {e}"
                    )

                self.root.after(0, self._update_progress, i + 1)

                if i < total - 1 and delay > 0 and not self._stop_event.is_set():
                    time.sleep(delay)

            # Generate reports if we have results
            if self.results:
                self.root.after(0, self._update_status, "Generating reports...")
                output_dir = Path(__file__).parent / "output"
                output_dir.mkdir(parents=True, exist_ok=True)

                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                md_path = str(output_dir / f"report_gui_{timestamp}.md")
                json_path = str(output_dir / f"report_gui_{timestamp}_data.json")
                html_path = str(output_dir / f"report_gui_{timestamp}.html")

                scout.generate_report(
                    self.results, md_path, json_output=json_path, html_output=html_path
                )

                self._last_html_report = html_path
                self._last_output_dir = str(output_dir)

                self.root.after(
                    0,
                    self._log_msg,
                    f"Reports saved:\n  MD:   {md_path}\n  JSON: {json_path}\n  HTML: {html_path}",
                )

            self.root.after(0, self._scan_finished, len(self.results), len(companies))

        except Exception as e:
            self.root.after(
                0, self._scan_finished, len(self.results), len(companies), str(e)
            )

    def _update_status(self, msg: str):
        self.status_var.set(msg)

    def _update_progress(self, value: int):
        self.progress["value"] = value

    def _log_msg(self, msg: str):
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, msg + "\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state="disabled")

    def _add_result_row(self, lead_dict: dict):
        tier = lead_dict["tier"]
        self.result_tree.insert(
            "",
            tk.END,
            values=(
                tier,
                lead_dict["company_name"],
                lead_dict["domain"],
                f"{lead_dict['total_score']:.1f}/{lead_dict['max_score']:.0f}",
                lead_dict["findings_count"],
                lead_dict["sector"],
            ),
        )

    def _scan_finished(self, done: int, total: int, error: str = None):
        self.scanning = False
        self.scan_btn.configure(state=tk.NORMAL)
        self.stop_btn.configure(state=tk.DISABLED)
        self.progress["value"] = self.progress["maximum"]

        if error:
            self.status_var.set(f"Scan failed: {error}")
            messagebox.showerror("Scan Error", error)
        else:
            hot = sum(1 for r in self.results_dicts if "HOT" in r.get("tier", ""))
            warm = sum(1 for r in self.results_dicts if "WARM" in r.get("tier", ""))
            cool = sum(1 for r in self.results_dicts if "COOL" in r.get("tier", ""))
            self.status_var.set(
                f"Scan complete: {done}/{total} companies | HOT: {hot}  WARM: {warm}  COOL: {cool}"
            )

    # ── Result interaction ───────────────────────────────────────

    def _on_result_double_click(self, event):
        selected = self.result_tree.selection()
        if not selected:
            return
        idx = self.result_tree.index(selected[0])
        if 0 <= idx < len(self.results_dicts):
            DetailWindow(self.root, self.results_dicts[idx])

    def _export_json(self):
        if not self.results_dicts:
            messagebox.showinfo("No Results", "Run a scan first.")
            return

        filepath = filedialog.asksaveasfilename(
            title="Export Results",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json")],
        )
        if not filepath:
            return

        data = {
            "generated_at": datetime.now().isoformat(),
            "total_companies": len(self.results_dicts),
            "leads": self.results_dicts,
        }
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        self.status_var.set(f"Exported to {Path(filepath).name}")

    def _open_html_report(self):
        path = getattr(self, "_last_html_report", None)
        if path and Path(path).exists():
            webbrowser.open(Path(path).as_uri())
        else:
            messagebox.showinfo(
                "No Report", "Run a scan first to generate an HTML report."
            )

    def _open_output_folder(self):
        output_dir = getattr(
            self, "_last_output_dir", str(Path(__file__).parent / "output")
        )
        if Path(output_dir).exists():
            os.startfile(output_dir)
        else:
            messagebox.showinfo("Not Found", "Output folder does not exist yet.")


def main():
    root = tk.Tk()
    root.iconname("Lead Scout")
    LeadScoutGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
