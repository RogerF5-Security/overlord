"""
OVERLORD :: Right Panel - Intelligence Board
Panel derecho con árbol de hallazgos en tiempo real, tabla de hosts vivos,
y exportación de reporte.
"""
import tkinter as tk
from tkinter import ttk, filedialog
import customtkinter as ctk
import json
import csv
from datetime import datetime
from typing import Optional


SEVERITY_BG = {
    "CRITICAL": "#3A0000",
    "HIGH":     "#3A1A00",
    "MEDIUM":   "#3A3A00",
    "LOW":      "#003A00",
    "INFO":     "#001A3A",
}

SEVERITY_FG = {
    "CRITICAL": "#FF3333",
    "HIGH":     "#FF8C00",
    "MEDIUM":   "#FFD700",
    "LOW":      "#00FF41",
    "INFO":     "#00BFFF",
}


class IntelTree(ctk.CTkFrame):
    """
    Árbol de hallazgos con columnas: Severidad | Host | Nombre | Herramienta.
    Se popula en tiempo real desde el pipeline.
    """

    COLS = ("severity", "host", "name", "tool", "found_at")
    COL_LABELS = ("SEV", "HOST", "FINDING", "TOOL", "TIMESTAMP")
    COL_WIDTHS = (70, 200, 220, 80, 90)

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="#0A0A0A", corner_radius=6, **kwargs)
        self._build()

    def _build(self):
        # Header
        ctk.CTkLabel(
            self, text="  ◈ FINDINGS BOARD",
            font=ctk.CTkFont(family="Courier New", size=11, weight="bold"),
            text_color="#FF3333", fg_color="#110000",
            anchor="w", height=26,
        ).pack(fill="x", pady=(0, 1))

        # Estilo del TreeView
        style = ttk.Style()
        style.theme_use("default")
        style.configure("Intel.Treeview",
            background="#0D0D0D",
            foreground="#CCCCCC",
            rowheight=22,
            fieldbackground="#0D0D0D",
            font=("Courier New", 9),
            borderwidth=0,
        )
        style.configure("Intel.Treeview.Heading",
            background="#111111",
            foreground="#00FF41",
            font=("Courier New", 9, "bold"),
            borderwidth=0,
            relief="flat",
        )
        style.map("Intel.Treeview",
            background=[("selected", "#1A2A1A")],
            foreground=[("selected", "#00FF41")],
        )

        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="both", expand=True)

        self._tree = ttk.Treeview(
            frame,
            columns=self.COLS,
            show="headings",
            style="Intel.Treeview",
            selectmode="browse",
        )

        for col, lbl, width in zip(self.COLS, self.COL_LABELS, self.COL_WIDTHS):
            self._tree.heading(col, text=lbl)
            self._tree.column(col, width=width, minwidth=40, stretch=(col == "name"))

        # Tags por severidad
        for sev, fg in SEVERITY_FG.items():
            bg = SEVERITY_BG.get(sev, "#0D0D0D")
            self._tree.tag_configure(sev.lower(), foreground=fg, background=bg)

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side="right", fill="y")
        self._tree.pack(side="left", fill="both", expand=True)

        # Detalle al seleccionar
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

    def add_finding(self, finding: dict):
        """Agrega un hallazgo al árbol (thread-safe vía after)."""
        self._tree.after(0, self._insert_finding, finding)

    def _insert_finding(self, finding: dict):
        sev = finding.get("severity", "INFO").upper()
        ts  = finding.get("found_at", "")[:19].replace("T", " ")
        host = finding.get("host", "")
        # Truncar host largo
        if len(host) > 30:
            host = "…" + host[-28:]

        self._tree.insert(
            "", 0,  # Insertar al inicio (más reciente arriba)
            values=(
                sev,
                host,
                finding.get("name", ""),
                finding.get("tool", ""),
                ts,
            ),
            tags=(sev.lower(),),
            iid=str(id(finding)) + str(datetime.now().timestamp()),
        )

    def clear(self):
        self._tree.after(0, lambda: self._tree.delete(*self._tree.get_children()))

    def _on_select(self, event):
        pass  # Detalle manejado por RightPanel


class HostsList(ctk.CTkFrame):
    """Lista compacta de hosts vivos con tecnologías detectadas."""

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="#0A0A0A", corner_radius=6, **kwargs)
        self._items: dict[str, str] = {}
        self._build()

    def _build(self):
        ctk.CTkLabel(
            self, text="  ◈ LIVE HOSTS",
            font=ctk.CTkFont(family="Courier New", size=11, weight="bold"),
            text_color="#00BFFF", fg_color="#00001A",
            anchor="w", height=26,
        ).pack(fill="x", pady=(0, 1))

        style = ttk.Style()
        style.configure("Hosts.Treeview",
            background="#0D0D0D", foreground="#AAAAAA",
            rowheight=20, fieldbackground="#0D0D0D",
            font=("Courier New", 9), borderwidth=0,
        )
        style.configure("Hosts.Treeview.Heading",
            background="#111111", foreground="#00BFFF",
            font=("Courier New", 9, "bold"), relief="flat",
        )
        style.map("Hosts.Treeview",
            background=[("selected", "#001A3A")],
        )

        frame = ctk.CTkFrame(self, fg_color="transparent")
        frame.pack(fill="both", expand=True)

        self._tree = ttk.Treeview(
            frame,
            columns=("host", "code", "tech"),
            show="headings",
            style="Hosts.Treeview",
        )
        self._tree.heading("host", text="HOST")
        self._tree.heading("code", text="CODE")
        self._tree.heading("tech", text="STACK")
        self._tree.column("host", width=220, stretch=True)
        self._tree.column("code", width=50)
        self._tree.column("tech", width=150)

        self._tree.tag_configure("alive",    foreground="#00FF41")
        self._tree.tag_configure("redirect", foreground="#FFD700")
        self._tree.tag_configure("forbidden",foreground="#FF8C00")

        sb = ttk.Scrollbar(frame, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self._tree.pack(side="left", fill="both", expand=True)

    def add_host(self, host: dict):
        self._tree.after(0, self._insert_host, host)

    def _insert_host(self, host: dict):
        h    = host.get("host", "")
        code = host.get("status_code", 0)
        tech = host.get("technologies", "")[:30]
        tag  = "alive" if code == 200 else \
               "redirect" if code in (301, 302, 307) else \
               "forbidden" if code == 403 else "alive"

        if h in self._items:
            # Actualizar existente
            iid = self._items[h]
            self._tree.item(iid, values=(h, code, tech), tags=(tag,))
        else:
            iid = self._tree.insert("", "end", values=(h, code, tech), tags=(tag,))
            self._items[h] = iid

    def clear(self):
        self._items.clear()
        self._tree.after(0, lambda: self._tree.delete(*self._tree.get_children()))


class RightPanel(ctk.CTkFrame):
    """Panel derecho completo: Intelligence Board."""

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="#0D0D0D", corner_radius=0, width=340, **kwargs)
        self._report_data: Optional[dict] = None
        self._build()

    def _build(self):
        self.pack_propagate(False)

        # ── Header ────────────────────────────────────────────────────────────
        header = ctk.CTkFrame(self, fg_color="#0A0A0A", corner_radius=0, height=44)
        header.pack(fill="x")
        header.pack_propagate(False)
        ctk.CTkLabel(
            header, text="◈ INTELLIGENCE BOARD",
            font=ctk.CTkFont(family="Courier New", size=13, weight="bold"),
            text_color="#FF3333",
        ).pack(pady=10)

        ctk.CTkFrame(self, fg_color="#1A0000", height=1).pack(fill="x")

        # ── Hosts vivos (1/3 del espacio) ─────────────────────────────────────
        self.hosts_list = HostsList(self)
        self.hosts_list.pack(fill="both", expand=False, padx=6, pady=(8, 4))
        self.hosts_list.configure(height=160)

        # ── Findings (2/3 del espacio) ────────────────────────────────────────
        self.intel_tree = IntelTree(self)
        self.intel_tree.pack(fill="both", expand=True, padx=6, pady=(4, 4))

        # ── Detail pane ───────────────────────────────────────────────────────
        detail_frame = ctk.CTkFrame(self, fg_color="#0A0A0A", corner_radius=6)
        detail_frame.pack(fill="x", padx=6, pady=(0, 4))

        ctk.CTkLabel(
            detail_frame, text="  ◈ PAYLOAD / DETAIL",
            font=ctk.CTkFont(family="Courier New", size=9, weight="bold"),
            text_color="#666666", anchor="w", height=22,
        ).pack(fill="x")

        self._detail_text = tk.Text(
            detail_frame,
            bg="#0D0D0D", fg="#888888",
            font=("Courier New", 9),
            height=5, wrap=tk.WORD,
            relief="flat", padx=6, pady=4,
            state="disabled", border=0,
            highlightthickness=0,
        )
        self._detail_text.pack(fill="x")

        # ── Export buttons ────────────────────────────────────────────────────
        exp_frame = ctk.CTkFrame(self, fg_color="transparent")
        exp_frame.pack(fill="x", padx=6, pady=(0, 8))
        exp_frame.columnconfigure((0, 1), weight=1)

        ctk.CTkButton(
            exp_frame, text="⬇ JSON",
            font=ctk.CTkFont(family="Courier New", size=10),
            fg_color="#111111", hover_color="#1A2A1A",
            text_color="#00FF41", border_color="#00FF41", border_width=1,
            height=28, corner_radius=4,
            command=self._export_json,
        ).grid(row=0, column=0, padx=(0, 2), sticky="ew")

        ctk.CTkButton(
            exp_frame, text="⬇ CSV",
            font=ctk.CTkFont(family="Courier New", size=10),
            fg_color="#111111", hover_color="#1A2A1A",
            text_color="#00BFFF", border_color="#00BFFF", border_width=1,
            height=28, corner_radius=4,
            command=self._export_csv,
        ).grid(row=0, column=1, padx=(2, 0), sticky="ew")

    # ── API Pública ───────────────────────────────────────────────────────────

    def add_finding(self, finding: dict):
        self.intel_tree.add_finding(finding)

    def add_host(self, host: dict):
        self.hosts_list.add_host(host)

    def set_detail(self, text: str):
        def _set():
            self._detail_text.configure(state="normal")
            self._detail_text.delete("1.0", "end")
            self._detail_text.insert("end", text)
            self._detail_text.configure(state="disabled")
        self._detail_text.after(0, _set)

    def set_report_data(self, data: dict):
        self._report_data = data

    def clear(self):
        self.intel_tree.clear()
        self.hosts_list.clear()
        self.set_detail("")

    def flash_critical(self):
        """Hace parpadear el header en rojo para alertas críticas."""
        def _flash(count=0):
            color = "#FF3333" if count % 2 == 0 else "#550000"
            self.intel_tree._header.configure(text_color=color)
            if count < 6:
                self.after(300, _flash, count + 1)
        self.after(0, _flash)

    # ── Exportación ───────────────────────────────────────────────────────────

    def _export_json(self):
        if not self._report_data:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile=f"overlord_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        )
        if path:
            with open(path, "w") as f:
                json.dump(self._report_data, f, indent=2, default=str)

    def _export_csv(self):
        if not self._report_data:
            return
        findings = self._report_data.get("findings", [])
        if not findings:
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile=f"overlord_findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
        )
        if path:
            with open(path, "w", newline="") as f:
                writer = csv.DictWriter(f, fieldnames=findings[0].keys())
                writer.writeheader()
                writer.writerows(findings)
