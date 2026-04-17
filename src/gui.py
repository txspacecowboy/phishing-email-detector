import os
import sys
import threading
import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, simpledialog, messagebox

sys.path.insert(0, os.path.dirname(__file__))
from analyzer import analyze_email, AnalysisResult
from gmail_fetch import connect, fetch_inbox, fetch_folder, list_folders, EmailSummary

# ── Theme ──────────────────────────────────────────────────────────────────────

APP_TITLE   = "Phishing Email Detector"
APP_VERSION = "2.0.0"

BG_ROOT   = "#f0f0f0"
BG_PANEL  = "#ffffff"
BG_INPUT  = "#fafafa"
FG_MAIN   = "#1a1a1a"
FG_MUTED  = "#555555"
FONT_MAIN = ("Segoe UI", 10)
FONT_BOLD = ("Segoe UI", 10, "bold")
FONT_HEAD = ("Segoe UI", 13, "bold")
FONT_MONO = ("Consolas", 9)

RISK_COLORS = {
    "HIGH":   {"bg": "#fde8e8", "fg": "#c0392b", "badge": "#e74c3c"},
    "MEDIUM": {"bg": "#fff8e1", "fg": "#d35400", "badge": "#e67e22"},
    "LOW":    {"bg": "#e8f4fd", "fg": "#1a5276", "badge": "#2980b9"},
    "CLEAN":  {"bg": "#e9f7ef", "fg": "#1e8449", "badge": "#27ae60"},
    "---":    {"bg": "#f0f0f0", "fg": "#555555", "badge": "#aaaaaa"},
}

SECTION_COLORS = {
    "header":  "#e8eaf6",
    "dns":     "#e1f5fe",
    "url":     "#fce4ec",
    "content": "#fff8e1",
    "vt":      "#e8f5e9",
}

# ── Main App ───────────────────────────────────────────────────────────────────

class PhishingDetectorApp:

    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_TITLE} v{APP_VERSION}")
        self.root.geometry("1000x750")
        self.root.minsize(800, 600)
        self.root.configure(bg=BG_ROOT)

        self._build_styles()
        self._build_ui()

    # ── Styles ─────────────────────────────────────────────────────────────────

    def _build_styles(self):
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TFrame",       background=BG_ROOT)
        style.configure("Card.TFrame",  background=BG_PANEL, relief="flat")
        style.configure("TLabel",       background=BG_ROOT, foreground=FG_MAIN, font=FONT_MAIN)
        style.configure("Card.TLabel",  background=BG_PANEL, foreground=FG_MAIN, font=FONT_MAIN)
        style.configure("Muted.TLabel", background=BG_PANEL, foreground=FG_MUTED, font=FONT_MAIN)
        style.configure("TCheckbutton", background=BG_PANEL, foreground=FG_MAIN, font=FONT_MAIN)
        style.configure("TEntry",       font=FONT_MAIN)
        style.configure("TNotebook",    background=BG_ROOT)
        style.configure("TNotebook.Tab", font=FONT_BOLD, padding=(10, 4))
        style.configure("Analyze.TButton",
            font=("Segoe UI", 11, "bold"), padding=(20, 8))
        style.map("Analyze.TButton",
            background=[("active", "#1a5276"), ("!active", "#2980b9")],
            foreground=[("active", "white"),   ("!active", "white")])

    # ── UI Layout ──────────────────────────────────────────────────────────────

    def _build_ui(self):
        # Title bar
        title_bar = tk.Frame(self.root, bg="#2980b9", pady=8)
        title_bar.pack(fill="x")
        tk.Label(title_bar, text=f"  {APP_TITLE}",
                 bg="#2980b9", fg="white",
                 font=("Segoe UI", 14, "bold")).pack(side="left")
        tk.Label(title_bar, text=f"v{APP_VERSION}  ",
                 bg="#2980b9", fg="#d0eaf8",
                 font=("Segoe UI", 9)).pack(side="right", anchor="s", pady=2)

        # Main content area
        content = ttk.Frame(self.root, padding=10)
        content.pack(fill="both", expand=True)
        content.columnconfigure(0, weight=3)
        content.columnconfigure(1, weight=1)
        content.rowconfigure(1, weight=1)
        content.rowconfigure(3, weight=2)

        self._build_input_panel(content)
        self._build_options_panel(content)
        self._build_analyze_row(content)
        self._build_results_panel(content)

    def _build_input_panel(self, parent):
        frame = tk.LabelFrame(parent, text=" Email Input ",
                              bg=BG_PANEL, fg=FG_MAIN, font=FONT_BOLD,
                              relief="groove", bd=1, padx=8, pady=6)
        frame.grid(row=0, column=0, rowspan=2, sticky="nsew", padx=(0, 6), pady=(0, 6))
        frame.rowconfigure(2, weight=1)
        frame.columnconfigure(0, weight=1)

        # File picker row
        file_row = tk.Frame(frame, bg=BG_PANEL)
        file_row.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        file_row.columnconfigure(1, weight=1)

        tk.Button(file_row, text="Browse .eml",
                  command=self._browse_file,
                  bg="#2980b9", fg="white", font=FONT_BOLD,
                  relief="flat", padx=10, pady=4,
                  cursor="hand2").grid(row=0, column=0, padx=(0, 8))

        self._file_label = tk.Label(file_row, text="No file selected",
                                    bg=BG_PANEL, fg=FG_MUTED,
                                    font=FONT_MAIN, anchor="w")
        self._file_label.grid(row=0, column=1, sticky="ew")

        tk.Button(file_row, text="📧 Gmail",
                  command=self._open_gmail_dialog,
                  bg="#c0392b", fg="white", font=FONT_BOLD,
                  relief="flat", padx=10, pady=4,
                  cursor="hand2").grid(row=0, column=2, padx=(8, 0))

        tk.Button(file_row, text="✕ Clear",
                  command=self._clear_input,
                  bg="#e0e0e0", fg=FG_MAIN, font=FONT_MAIN,
                  relief="flat", padx=8, pady=4,
                  cursor="hand2").grid(row=0, column=3, padx=(8, 0))

        # Divider label
        tk.Label(frame, text="— or paste raw email text below —",
                 bg=BG_PANEL, fg=FG_MUTED, font=("Segoe UI", 9, "italic")
                 ).grid(row=1, column=0, sticky="w", pady=(0, 4))

        # Text input
        self._email_text = scrolledtext.ScrolledText(
            frame, font=FONT_MONO, bg=BG_INPUT, fg=FG_MAIN,
            relief="flat", bd=1, wrap="none",
            highlightbackground="#cccccc", highlightthickness=1,
        )
        self._email_text.grid(row=2, column=0, sticky="nsew")

    def _build_options_panel(self, parent):
        frame = tk.LabelFrame(parent, text=" Options ",
                              bg=BG_PANEL, fg=FG_MAIN, font=FONT_BOLD,
                              relief="groove", bd=1, padx=10, pady=8)
        frame.grid(row=0, column=1, sticky="nsew", pady=(0, 6))

        self._dns_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="Live DNS checks\n(SPF/DKIM/DMARC)",
                        variable=self._dns_var,
                        style="TCheckbutton").pack(anchor="w", pady=(0, 12))

        tk.Label(frame, text="VirusTotal API Key:",
                 bg=BG_PANEL, fg=FG_MAIN, font=FONT_BOLD).pack(anchor="w")
        tk.Label(frame, text="(free key at virustotal.com)",
                 bg=BG_PANEL, fg=FG_MUTED,
                 font=("Segoe UI", 8, "italic")).pack(anchor="w", pady=(0, 4))

        self._vt_key_var = tk.StringVar(value=os.environ.get("VT_API_KEY", ""))
        vt_entry = ttk.Entry(frame, textvariable=self._vt_key_var,
                             show="*", width=22)
        vt_entry.pack(anchor="w", fill="x")

        # Show/hide toggle
        self._show_key = tk.BooleanVar(value=False)
        def _toggle_show():
            vt_entry.config(show="" if self._show_key.get() else "*")
        ttk.Checkbutton(frame, text="Show key",
                        variable=self._show_key,
                        command=_toggle_show).pack(anchor="w", pady=(2, 0))

    def _build_analyze_row(self, parent):
        row = ttk.Frame(parent)
        row.grid(row=2, column=1, sticky="ew", pady=(0, 6))

        self._analyze_btn = ttk.Button(
            row, text="ANALYZE",
            style="Analyze.TButton",
            command=self._start_analysis,
        )
        self._analyze_btn.pack(fill="x")

        self._status_label = tk.Label(row, text="", bg=BG_ROOT,
                                      fg=FG_MUTED, font=("Segoe UI", 8))
        self._status_label.pack(pady=(4, 0))

    def _build_results_panel(self, parent):
        outer = tk.LabelFrame(parent, text=" Results ",
                              bg=BG_PANEL, fg=FG_MAIN, font=FONT_BOLD,
                              relief="groove", bd=1, padx=8, pady=8)
        outer.grid(row=3, column=0, columnspan=2, sticky="nsew", pady=(6, 0))
        outer.rowconfigure(1, weight=1)
        outer.columnconfigure(0, weight=1)

        # Risk badge row
        badge_row = tk.Frame(outer, bg=BG_PANEL)
        badge_row.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        self._risk_badge = tk.Label(badge_row, text="  ---  ",
                                    bg="#aaaaaa", fg="white",
                                    font=("Segoe UI", 15, "bold"),
                                    relief="flat", padx=14, pady=4)
        self._risk_badge.pack(side="left")

        self._score_label = tk.Label(badge_row, text="Score: --/100",
                                     bg=BG_PANEL, fg=FG_MAIN,
                                     font=("Segoe UI", 12))
        self._score_label.pack(side="left", padx=16)

        self._findings_label = tk.Label(badge_row, text="",
                                        bg=BG_PANEL, fg=FG_MUTED,
                                        font=FONT_MAIN)
        self._findings_label.pack(side="left")

        # Notebook for categorized findings
        self._notebook = ttk.Notebook(outer)
        self._notebook.grid(row=1, column=0, sticky="nsew")

        self._tabs: dict[str, tk.Text] = {}
        tab_defs = [
            ("header",  "Header"),
            ("dns",     "DNS"),
            ("url",     "URLs"),
            ("content", "Content"),
            ("vt",      "VirusTotal"),
        ]
        for key, label in tab_defs:
            frame = ttk.Frame(self._notebook)
            self._notebook.add(frame, text=label)
            frame.rowconfigure(0, weight=1)
            frame.columnconfigure(0, weight=1)
            txt = tk.Text(frame, font=FONT_MONO, bg=BG_INPUT, fg=FG_MAIN,
                          relief="flat", state="disabled", wrap="word",
                          highlightthickness=0)
            sb = ttk.Scrollbar(frame, orient="vertical", command=txt.yview)
            txt.configure(yscrollcommand=sb.set)
            txt.grid(row=0, column=0, sticky="nsew")
            sb.grid(row=0, column=1, sticky="ns")
            txt.tag_configure("high",   foreground="#c0392b", font=FONT_BOLD)
            txt.tag_configure("medium", foreground="#d35400", font=FONT_BOLD)
            txt.tag_configure("low",    foreground="#1a5276")
            txt.tag_configure("score",  foreground="#7f8c8d", font=FONT_BOLD)
            txt.tag_configure("url",    foreground="#555555", font=("Consolas", 8))
            txt.tag_configure("info",   foreground="#888888", font=("Segoe UI", 9, "italic"))
            self._tabs[key] = txt

    # ── Actions ────────────────────────────────────────────────────────────────

    def _browse_file(self):
        path = filedialog.askopenfilename(
            title="Select email file",
            filetypes=[("Email files", "*.eml *.msg *.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                content = fh.read()
            self._email_text.delete("1.0", "end")
            self._email_text.insert("1.0", content)
            self._file_label.config(text=os.path.basename(path), fg=FG_MAIN)
        except Exception as e:
            self._file_label.config(text=f"Error: {e}", fg="#c0392b")

    def _open_gmail_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Connect to Gmail")
        dialog.geometry("420x220")
        dialog.resizable(False, False)
        dialog.configure(bg=BG_PANEL)
        dialog.grab_set()

        tk.Label(dialog, text="Gmail Address:",
                 bg=BG_PANEL, fg=FG_MAIN, font=FONT_BOLD).grid(
                 row=0, column=0, sticky="w", padx=16, pady=(20, 4))
        email_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=email_var, width=35).grid(
            row=0, column=1, padx=(0, 16), pady=(20, 4))

        tk.Label(dialog, text="App Password:",
                 bg=BG_PANEL, fg=FG_MAIN, font=FONT_BOLD).grid(
                 row=1, column=0, sticky="w", padx=16, pady=4)
        pass_var = tk.StringVar()
        ttk.Entry(dialog, textvariable=pass_var, show="*", width=35).grid(
            row=1, column=1, padx=(0, 16), pady=4)

        tk.Label(dialog,
                 text="Use your Gmail App Password\n(not your regular password)",
                 bg=BG_PANEL, fg=FG_MUTED,
                 font=("Segoe UI", 8, "italic")).grid(
                 row=2, column=0, columnspan=2, pady=(0, 12))

        status = tk.Label(dialog, text="", bg=BG_PANEL,
                          fg="#c0392b", font=("Segoe UI", 9))
        status.grid(row=3, column=0, columnspan=2)

        def _connect():
            addr = email_var.get().strip()
            pwd  = pass_var.get().strip()
            if not addr or not pwd:
                status.config(text="Please fill in both fields.")
                return
            connect_btn.config(state="disabled", text="Connecting…")
            status.config(text="", fg=FG_MUTED)

            def _run():
                try:
                    conn = connect(addr, pwd)
                    emails = fetch_inbox(conn, limit=30)
                    self.root.after(0, lambda: (dialog.destroy(),
                                                self._show_inbox(conn, emails)))
                except Exception as e:
                    err = str(e)
                    self.root.after(0, lambda: (
                        status.config(text=f"Error: {err}", fg="#c0392b"),
                        connect_btn.config(state="normal", text="Connect")
                    ))
            threading.Thread(target=_run, daemon=True).start()

        connect_btn = tk.Button(dialog, text="Connect",
                                command=_connect,
                                bg="#2980b9", fg="white", font=FONT_BOLD,
                                relief="flat", padx=16, pady=6, cursor="hand2")
        connect_btn.grid(row=4, column=0, columnspan=2, pady=(8, 0))

    def _show_inbox(self, conn, emails: list):
        win = tk.Toplevel(self.root)
        win.title("Gmail Inbox — Select an Email to Analyze")
        win.geometry("750x460")
        win.configure(bg=BG_PANEL)
        win.grab_set()

        # Folder bar
        top = tk.Frame(win, bg=BG_PANEL)
        top.pack(fill="x", padx=10, pady=(10, 0))
        tk.Label(top, text="Folder:", bg=BG_PANEL,
                 font=FONT_BOLD).pack(side="left")
        folder_var = tk.StringVar(value="INBOX")
        folder_entry = ttk.Entry(top, textvariable=folder_var, width=25)
        folder_entry.pack(side="left", padx=6)

        def _load_folder():
            folder = folder_var.get().strip()
            refresh_btn.config(state="disabled", text="Loading…")
            def _run():
                try:
                    new_emails = fetch_folder(conn, folder, limit=30)
                    self.root.after(0, lambda: _populate(new_emails))
                except Exception as e:
                    self.root.after(0, lambda: messagebox.showerror(
                        "Folder Error", str(e), parent=win))
                finally:
                    self.root.after(0, lambda: refresh_btn.config(
                        state="normal", text="Load"))
            threading.Thread(target=_run, daemon=True).start()

        refresh_btn = tk.Button(top, text="Load", command=_load_folder,
                                bg="#2980b9", fg="white", font=FONT_BOLD,
                                relief="flat", padx=10, pady=3, cursor="hand2")
        refresh_btn.pack(side="left")
        tk.Label(top, text="(e.g. INBOX, [Gmail]/Spam, [Gmail]/Sent Mail)",
                 bg=BG_PANEL, fg=FG_MUTED,
                 font=("Segoe UI", 8, "italic")).pack(side="left", padx=8)

        # Email list
        cols = ("From", "Subject", "Date")
        tree = ttk.Treeview(win, columns=cols, show="headings",
                            selectmode="browse", height=16)
        tree.heading("From",    text="From")
        tree.heading("Subject", text="Subject")
        tree.heading("Date",    text="Date")
        tree.column("From",    width=200, anchor="w")
        tree.column("Subject", width=320, anchor="w")
        tree.column("Date",    width=160, anchor="w")

        sb = ttk.Scrollbar(win, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=sb.set)
        tree.pack(side="left", fill="both", expand=True, padx=(10, 0), pady=8)
        sb.pack(side="left", fill="y", pady=8)

        self._inbox_emails = emails

        def _populate(email_list):
            self._inbox_emails = email_list
            for row in tree.get_children():
                tree.delete(row)
            for i, em in enumerate(email_list):
                subject = em.subject[:60] + "…" if len(em.subject) > 60 else em.subject
                sender  = em.sender[:40] + "…" if len(em.sender) > 40 else em.sender
                tree.insert("", "end", iid=str(i),
                            values=(sender, subject, em.date[:25]))

        _populate(emails)

        def _load_selected(event=None):
            sel = tree.selection()
            if not sel:
                return
            idx = int(sel[0])
            em = self._inbox_emails[idx]
            self._email_text.delete("1.0", "end")
            self._email_text.insert("1.0", em.raw)
            self._file_label.config(
                text=f"Gmail: {em.subject[:50]}", fg=FG_MAIN)
            win.destroy()

        tree.bind("<Double-1>", _load_selected)

        tk.Button(win, text="Load & Analyze Selected",
                  command=_load_selected,
                  bg="#27ae60", fg="white", font=FONT_BOLD,
                  relief="flat", padx=14, pady=6,
                  cursor="hand2").pack(pady=(0, 10))

    def _clear_input(self):
        self._email_text.delete("1.0", "end")
        self._file_label.config(text="No file selected", fg=FG_MUTED)
        self._reset_results()

    def _start_analysis(self):
        raw = self._email_text.get("1.0", "end").strip()
        if not raw:
            self._set_status("Paste an email or load a .eml file first.", error=True)
            return

        self._analyze_btn.state(["disabled"])
        self._set_status("Analyzing…")
        self._reset_results()

        vt_key  = self._vt_key_var.get().strip() or None
        live_dns = self._dns_var.get()

        def _run():
            try:
                result = analyze_email(raw, vt_api_key=vt_key, live_dns=live_dns)
                self.root.after(0, lambda: self._display_result(result))
            except Exception as exc:
                self.root.after(0, lambda: self._set_status(f"Error: {exc}", error=True))
            finally:
                self.root.after(0, lambda: self._analyze_btn.state(["!disabled"]))

        threading.Thread(target=_run, daemon=True).start()

    # ── Display ────────────────────────────────────────────────────────────────

    def _display_result(self, result: AnalysisResult):
        colors = RISK_COLORS.get(result.risk_level, RISK_COLORS["---"])
        self._risk_badge.config(text=f"  {result.risk_level}  ",
                                bg=colors["badge"])
        self._score_label.config(text=f"Score: {result.raw_score}/100",
                                 fg=colors["fg"])
        self._findings_label.config(
            text=f"{result.total_findings} finding(s)" if result.total_findings else "No suspicious indicators")

        self._populate_tab("header",  result.header_findings)
        self._populate_tab("dns",     result.dns_findings)
        self._populate_tab("url",     result.url_findings,  show_url=True)
        self._populate_tab("content", result.content_findings)
        self._populate_tab("vt",      result.vt_findings,   show_url=True)

        # Update tab titles with finding counts
        tab_counts = {
            0: len(result.header_findings),
            1: len(result.dns_findings),
            2: len(result.url_findings),
            3: len(result.content_findings),
            4: len(result.vt_findings),
        }
        labels = ["Header", "DNS", "URLs", "Content", "VirusTotal"]
        for i, (label, count) in enumerate(zip(labels, tab_counts.values())):
            self._notebook.tab(i, text=f"{label} ({count})" if count else label)

        self._set_status("Analysis complete.")

    def _populate_tab(self, key: str, findings, show_url: bool = False):
        txt = self._tabs[key]
        txt.config(state="normal")
        txt.delete("1.0", "end")

        if not findings:
            txt.insert("end", "  No findings in this category.", "info")
        else:
            for f in findings:
                score = f.score
                score_str = f"  [{score:+3d}]  "
                tag = "high" if score >= 25 else "medium" if score >= 10 else "low" if score > 0 else "info"
                txt.insert("end", score_str, "score")
                txt.insert("end", f.reason + "\n", tag)
                if show_url and getattr(f, "url", ""):
                    url = f.url
                    display = url[:90] + "…" if len(url) > 90 else url
                    txt.insert("end", f"         {display}\n", "url")

        txt.config(state="disabled")

    def _reset_results(self):
        self._risk_badge.config(text="  ---  ", bg="#aaaaaa")
        self._score_label.config(text="Score: --/100", fg=FG_MAIN)
        self._findings_label.config(text="")
        labels = ["Header", "DNS", "URLs", "Content", "VirusTotal"]
        for i, label in enumerate(labels):
            self._notebook.tab(i, text=label)
        for txt in self._tabs.values():
            txt.config(state="normal")
            txt.delete("1.0", "end")
            txt.config(state="disabled")

    def _set_status(self, msg: str, error: bool = False):
        self._status_label.config(text=msg,
                                  fg="#c0392b" if error else FG_MUTED)


# ── Entry point ────────────────────────────────────────────────────────────────

def launch():
    root = tk.Tk()
    app = PhishingDetectorApp(root)
    root.mainloop()


if __name__ == "__main__":
    launch()
