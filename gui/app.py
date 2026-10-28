import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from core import report, scanner
BG = "#1e1e2e" 
PANEL = "#45475a"
PANEL_HI = "#11111b"
BORDER = "#7dc4e4"
TEXT = "#c6d0f5"
MUTED = "#85c1dc"
ACCENT = "#99d1db"  
SELECT = "#81c8be" 
RISK_COLORS = {
    "LOW":    {"background": "#a6d189", "foreground": "#51576d"},
    "MEDIUM": {"background": "#ef9f76", "foreground": "#51576d"},
    "HIGH":   {"background": "#e78284", "foreground": "#51576d"},
}
RISK_TEXT = {"LOW": "#a6d189", "MEDIUM": "#ef9f76", "HIGH": "#e78284"}
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("FILYZER")
        self.geometry("1100x700")
        self.reports = []
        self.bad_hashes = set()
        self.q = queue.Queue()
        self._sel_iid = None 
        self._apply_theme()
        self._build()
    def _apply_theme(self):
        self.configure(bg=BG)
        s = ttk.Style(self)
        s.theme_use("clam")  
        s.configure(".", background=BG, foreground=TEXT, fieldbackground=BG,
                    bordercolor=BORDER, focuscolor=BG)
        s.configure("TFrame", background=BG)
        s.configure("TLabel", background=BG, foreground=MUTED)
        s.configure("TButton", background=PANEL_HI, foreground=TEXT,
                    padding=(14, 7), borderwidth=1, relief="flat")
        s.map("TButton",
              background=[("pressed", SELECT), ("active", ACCENT)],
              foreground=[("active", "#ffffff")])
        s.configure("Treeview", background=BG, fieldbackground=BG, foreground=TEXT,
                    rowheight=26, borderwidth=0, bordercolor=BG,
                    lightcolor=BG, darkcolor=BG)
        s.map("Treeview",
              background=[("selected", SELECT)],
              foreground=[("selected", "#ffffff")])
        s.configure("Treeview.Heading", background=PANEL, foreground=TEXT,
                    relief="flat", padding=(8, 6))
        s.map("Treeview.Heading", background=[("active", PANEL_HI)])
        s.configure("Horizontal.TProgressbar", troughcolor=PANEL, background=ACCENT,
                    borderwidth=0, thickness=6)
        s.configure("Vertical.TScrollbar", background=PANEL_HI, troughcolor=BG,
                    bordercolor=BG, lightcolor=PANEL_HI, darkcolor=PANEL_HI,
                    arrowcolor=MUTED)
        s.map("Vertical.TScrollbar", background=[("active", BORDER)])
    def _build(self):
        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=10, pady=(10, 6))
        ttk.Button(bar, text="Scan File", command=self.scan_file).pack(side="left", padx=2)
        ttk.Button(bar, text="Scan Folder", command=self.scan_folder).pack(side="left", padx=2)
        ttk.Button(bar, text="Load Bad-Hash List", command=self.load_hashes).pack(side="left", padx=2)
        ttk.Button(bar, text="Export HTML Report", command=self.export).pack(side="left", padx=2)
        self.status = ttk.Label(bar, text="Ready")
        self.status.pack(side="right")
        self.progress = ttk.Progressbar(self, mode="determinate")
        self.progress.pack(fill="x", padx=10, pady=(0, 6))
        table = ttk.Frame(self)
        table.pack(fill="both", expand=True, padx=10)
        cols = ("file", "type", "entropy", "risk", "score")
        self.tree = ttk.Treeview(table, columns=cols, show="headings", height=14,
                                 selectmode="browse")
        for c, w in zip(cols, (520, 90, 80, 90, 70)):
            self.tree.heading(c, text=c.capitalize())
            self.tree.column(c, width=w, anchor="w")
        for tag, colors in RISK_COLORS.items():
            self.tree.tag_configure(tag, **colors)
            self.tree.tag_configure(tag + "_SEL", background=SELECT, foreground="#ffffff")
        scroll = ttk.Scrollbar(table, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self.show_details)
        self.details = tk.Text(
            self, height=14, wrap="word", state="disabled", font="TkFixedFont",
            bg=PANEL, fg=TEXT, insertbackground=TEXT, selectbackground=SELECT,
            relief="flat", padx=12, pady=10,
            highlightthickness=1, highlightbackground=BORDER, highlightcolor=BORDER)
        for risk, color in RISK_TEXT.items():
            self.details.tag_configure(risk, foreground=color)
        self.details.pack(fill="x", padx=10, pady=10)
    def scan_file(self):
        path = filedialog.askopenfilename()
        if path:
            self._start(scanner.collect_files(path))
    def scan_folder(self):
        path = filedialog.askdirectory()
        if path:
            self._start(scanner.collect_files(path))
    def load_hashes(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All", "*.*")])
        if path:
            with open(path, encoding="utf-8") as f:
                self.bad_hashes = {ln.strip().lower() for ln in f if ln.strip()}
            self.status.config(text=f"{len(self.bad_hashes)} bad hashes loaded")
    def export(self):
        if not self.reports:
            messagebox.showinfo("Nothing to export", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML", "*.html")])
        if path:
            report.export_html(self.reports, path)
            self.status.config(text=f"Saved {path}")
    def _start(self, files):
        self.reports.clear()
        self.tree.delete(*self.tree.get_children())
        self._sel_iid = None
        self.progress.config(maximum=max(len(files), 1), value=0)
        threading.Thread(target=self._worker, args=(files,), daemon=True).start()
        self.after(100, self._poll)
    def _worker(self, files):
        for f in files:
            self.q.put(("report", scanner.analyze_file(f, self.bad_hashes)))
        self.q.put(("done", len(files)))
    def _poll(self):
        finished = False
        while not self.q.empty():
            kind, payload = self.q.get()
            if kind == "report":
                self.reports.append(payload)
                i = len(self.reports) - 1
                self.tree.insert("", "end", iid=str(i), tags=(payload.risk,), values=(
                    payload.path, payload.detected_type, f"{payload.entropy:.2f}",
                    payload.risk, payload.score))
                self.progress.step(1)
            else:
                self.status.config(text=f"Done: {payload} files scanned")
                finished = True
        if not finished:
            self.after(100, self._poll)
    def show_details(self, _event):
        if self._sel_iid is not None and self.tree.exists(self._sel_iid):
            old = self.reports[int(self._sel_iid)]
            self.tree.item(self._sel_iid, tags=(old.risk,))
        self._sel_iid = None
        sel = self.tree.selection()
        if not sel:
            return
        r = self.reports[int(sel[0])]
        self.tree.item(sel[0], tags=(r.risk + "_SEL",))
        self._sel_iid = sel[0]
        lines = report.describe(r).splitlines()
        self.details.config(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", "\n".join(lines))
        for n, line in enumerate(lines, 1):
            if line.startswith("Risk:"):
                self.details.tag_add(r.risk, f"{n}.0", f"{n}.end")
        self.details.config(state="disabled")