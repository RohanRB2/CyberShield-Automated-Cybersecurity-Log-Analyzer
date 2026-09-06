"""
CyberShield - Main Dashboard (Tkinter GUI)
------------------------------------------
A desktop dashboard that:
  1. Loads a log file (CSV or raw text)
  2. Runs the detection engine (log_analyzer.py)
  3. Displays summary stats, a findings table, and matplotlib charts
  4. Lets the user export a CSV/TXT report

Run with:  python3 dashboard.py
"""

import os
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

import log_analyzer
import report_generator

# ---------------------------------------------------------------------------
# Color palette (dark "SOC dashboard" theme)
# ---------------------------------------------------------------------------
BG_DARK = "#0f1420"
BG_PANEL = "#161d2e"
ACCENT = "#00e5ff"
TEXT_LIGHT = "#e6edf3"
TEXT_DIM = "#8b98a9"
SEVERITY_COLORS = {
    "Critical": "#ff3b5c",
    "High": "#ff8c42",
    "Medium": "#ffd23f",
    "Low": "#4dd4ac",
}

plt.rcParams.update({
    "figure.facecolor": BG_PANEL,
    "axes.facecolor": BG_PANEL,
    "axes.edgecolor": TEXT_DIM,
    "axes.labelcolor": TEXT_LIGHT,
    "text.color": TEXT_LIGHT,
    "xtick.color": TEXT_DIM,
    "ytick.color": TEXT_DIM,
    "font.size": 8,
})


class CyberShieldApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("🛡️ CyberShield — Automated Cybersecurity Log Analyzer")
        self.geometry("1280x800")
        self.configure(bg=BG_DARK)

        self.df = None
        self.findings_df = None
        self.stats = None
        self.log_path = tk.StringVar(value="No log file loaded")

        self._build_layout()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------
    def _build_layout(self):
        self._build_header()
        self._build_body()
        self._build_statusbar()

    def _build_header(self):
        header = tk.Frame(self, bg=BG_PANEL, height=70)
        header.pack(side="top", fill="x")

        title = tk.Label(header, text="🛡️  CyberShield",
                          font=("Segoe UI", 20, "bold"),
                          bg=BG_PANEL, fg=ACCENT)
        title.pack(side="left", padx=20, pady=15)

        subtitle = tk.Label(header, text="Automated Cybersecurity Log Analyzer",
                             font=("Segoe UI", 11), bg=BG_PANEL, fg=TEXT_DIM)
        subtitle.pack(side="left", pady=15)

        btn_frame = tk.Frame(header, bg=BG_PANEL)
        btn_frame.pack(side="right", padx=20)

        self._make_button(btn_frame, "📂 Load Log File", self.load_log_file).pack(side="left", padx=5)
        self._make_button(btn_frame, "⚙️ Run Analysis", self.run_analysis).pack(side="left", padx=5)
        self._make_button(btn_frame, "📄 Export Report", self.export_report).pack(side="left", padx=5)

    def _make_button(self, parent, text, command):
        return tk.Button(parent, text=text, command=command,
                          bg="#1c2740", fg=TEXT_LIGHT, activebackground=ACCENT,
                          activeforeground="#000000", relief="flat",
                          font=("Segoe UI", 10), padx=12, pady=6, cursor="hand2")

    def _build_body(self):
        body = tk.Frame(self, bg=BG_DARK)
        body.pack(fill="both", expand=True, padx=15, pady=10)

        # Left: summary cards + findings table
        left = tk.Frame(body, bg=BG_DARK)
        left.pack(side="left", fill="both", expand=True, padx=(0, 10))

        self.summary_frame = tk.Frame(left, bg=BG_DARK)
        self.summary_frame.pack(fill="x", pady=(0, 10))
        self._render_summary_cards({})

        table_label = tk.Label(left, text="Detected Findings",
                                font=("Segoe UI", 12, "bold"), bg=BG_DARK, fg=TEXT_LIGHT)
        table_label.pack(anchor="w")

        self._build_findings_table(left)

        # Right: charts
        right = tk.Frame(body, bg=BG_PANEL, width=480)
        right.pack(side="right", fill="both")
        right.pack_propagate(False)

        charts_label = tk.Label(right, text="Visual Analytics",
                                 font=("Segoe UI", 12, "bold"), bg=BG_PANEL, fg=TEXT_LIGHT)
        charts_label.pack(anchor="w", padx=10, pady=(10, 0))

        self.chart_container = tk.Frame(right, bg=BG_PANEL)
        self.chart_container.pack(fill="both", expand=True, padx=10, pady=10)

    def _build_findings_table(self, parent):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview",
                         background=BG_PANEL, fieldbackground=BG_PANEL,
                         foreground=TEXT_LIGHT, rowheight=26, borderwidth=0,
                         font=("Segoe UI", 9))
        style.configure("Treeview.Heading",
                         background="#1c2740", foreground=ACCENT,
                         font=("Segoe UI", 9, "bold"))
        style.map("Treeview", background=[("selected", "#243354")])

        columns = ("severity", "type", "ip_address", "username", "details", "timestamp")
        self.tree = ttk.Treeview(parent, columns=columns, show="headings", height=22)

        headings = {
            "severity": "Severity", "type": "Finding Type", "ip_address": "IP Address",
            "username": "User/Detail", "details": "Description", "timestamp": "Timestamp"
        }
        widths = {"severity": 80, "type": 200, "ip_address": 120,
                  "username": 130, "details": 320, "timestamp": 140}

        for col in columns:
            self.tree.heading(col, text=headings[col])
            self.tree.column(col, width=widths[col], anchor="w")

        vsb = ttk.Scrollbar(parent, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        for sev, color in SEVERITY_COLORS.items():
            self.tree.tag_configure(sev, foreground=color)

    def _build_statusbar(self):
        bar = tk.Frame(self, bg="#0a0e17", height=28)
        bar.pack(side="bottom", fill="x")
        self.status_label = tk.Label(bar, textvariable=self.log_path,
                                      bg="#0a0e17", fg=TEXT_DIM, font=("Segoe UI", 9),
                                      anchor="w")
        self.status_label.pack(side="left", padx=10)

    # ------------------------------------------------------------------
    # Summary cards
    # ------------------------------------------------------------------
    def _render_summary_cards(self, stats):
        for widget in self.summary_frame.winfo_children():
            widget.destroy()

        cards = [
            ("Total Events", stats.get("total_events", "—"), ACCENT),
            ("Failed Logins", stats.get("total_failed", "—"), "#ff8c42"),
            ("Unique IPs", stats.get("unique_ips", "—"), "#4dd4ac"),
            ("Findings", stats.get("total_findings", "—"), "#ff3b5c"),
        ]

        for label, value, color in cards:
            card = tk.Frame(self.summary_frame, bg=BG_PANEL, padx=15, pady=10)
            card.pack(side="left", fill="x", expand=True, padx=5)
            tk.Label(card, text=str(value), font=("Segoe UI", 20, "bold"),
                     bg=BG_PANEL, fg=color).pack(anchor="w")
            tk.Label(card, text=label, font=("Segoe UI", 9),
                     bg=BG_PANEL, fg=TEXT_DIM).pack(anchor="w")

    # ------------------------------------------------------------------
    # Actions
    # ------------------------------------------------------------------
    def load_log_file(self):
        path = filedialog.askopenfilename(
            title="Select a log file",
            filetypes=[("CSV files", "*.csv"), ("Text/log files", "*.log *.txt"), ("All files", "*.*")]
        )
        if not path:
            return

        try:
            if path.lower().endswith(".csv"):
                self.df = log_analyzer.load_csv_log(path)
            else:
                self.df = log_analyzer.parse_raw_log_file(path)
                if self.df.empty:
                    messagebox.showwarning("No matches", "No recognizable login events found in this file.")
                    return
        except Exception as e:
            messagebox.showerror("Error loading file", str(e))
            return

        self.log_path.set(f"Loaded: {path}  ({len(self.df)} events)")
        messagebox.showinfo("Log Loaded", f"Successfully loaded {len(self.df)} log entries.\nClick 'Run Analysis' next.")

    def run_analysis(self):
        if self.df is None or self.df.empty:
            messagebox.showwarning("No Data", "Please load a log file first.")
            return

        self.findings_df = log_analyzer.run_full_analysis(self.df)
        self.stats = log_analyzer.compute_summary_stats(self.df, self.findings_df)

        self._render_summary_cards(self.stats)
        self._populate_table()
        self._render_charts()

    def _populate_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

        if self.findings_df is None or self.findings_df.empty:
            return

        for _, row in self.findings_df.iterrows():
            self.tree.insert("", "end", values=(
                row["severity"], row["type"], row["ip_address"],
                row["username"], row["details"],
                row["timestamp"].strftime("%Y-%m-%d %H:%M:%S") if hasattr(row["timestamp"], "strftime") else row["timestamp"]
            ), tags=(row["severity"],))

    def _render_charts(self):
        for widget in self.chart_container.winfo_children():
            widget.destroy()

        fig, axes = plt.subplots(3, 1, figsize=(4.4, 7.2))
        fig.subplots_adjust(hspace=0.6)

        # Chart 1: Severity breakdown (bar)
        sev_counts = self.stats.get("severity_counts", {})
        if sev_counts:
            order = ["Critical", "High", "Medium", "Low"]
            labels = [s for s in order if s in sev_counts]
            values = [sev_counts[s] for s in labels]
            colors = [SEVERITY_COLORS[s] for s in labels]
            axes[0].bar(labels, values, color=colors)
        axes[0].set_title("Findings by Severity", fontsize=10, color=TEXT_LIGHT)

        # Chart 2: Top offending IPs (horizontal bar)
        top_ips = self.stats.get("top_offending_ips", {})
        if top_ips:
            ips = list(top_ips.keys())[::-1]
            counts = list(top_ips.values())[::-1]
            axes[1].barh(ips, counts, color=ACCENT)
        axes[1].set_title("Top Offending IPs (Failed Logins)", fontsize=10, color=TEXT_LIGHT)
        axes[1].tick_params(axis='y', labelsize=7)

        # Chart 3: Success vs Failed (pie)
        success = self.stats.get("total_success", 0)
        failed = self.stats.get("total_failed", 0)
        if success + failed > 0:
            axes[2].pie([success, failed], labels=["Success", "Failed"],
                        colors=["#4dd4ac", "#ff3b5c"], autopct="%1.0f%%",
                        textprops={"color": TEXT_LIGHT, "fontsize": 8})
        axes[2].set_title("Login Outcome Ratio", fontsize=10, color=TEXT_LIGHT)

        canvas = FigureCanvasTkAgg(fig, master=self.chart_container)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True)
        plt.close(fig)

    def export_report(self):
        if self.findings_df is None:
            messagebox.showwarning("Nothing to Export", "Please run an analysis first.")
            return

        csv_path = report_generator.export_findings_csv(self.findings_df)
        txt_path = report_generator.export_summary_txt(self.stats)

        messagebox.showinfo(
            "Report Exported",
            f"Findings CSV:\n{csv_path}\n\nSummary report:\n{txt_path}"
        )


if __name__ == "__main__":
    app = CyberShieldApp()
    app.mainloop()
