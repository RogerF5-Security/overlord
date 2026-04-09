"""
OVERLORD :: Left Panel - Pipeline Control
Panel de control táctico con checkboxes de fases, configuración de target
y el botón ENGAGE.
"""
import tkinter as tk
import customtkinter as ctk
from typing import Callable


class StatCard(ctk.CTkFrame):
    """Tarjeta de estadística individual."""

    def __init__(self, master, label: str, color: str = "#00FF41", **kwargs):
        super().__init__(master, fg_color="#111111", corner_radius=6, **kwargs)
        self._val = ctk.CTkLabel(
            self, text="0",
            font=ctk.CTkFont(family="Courier New", size=22, weight="bold"),
            text_color=color,
        )
        self._val.pack(pady=(8, 0))
        ctk.CTkLabel(
            self, text=label,
            font=ctk.CTkFont(family="Courier New", size=9),
            text_color="#666666",
        ).pack(pady=(0, 6))

    def set(self, value):
        self._val.after(0, lambda: self._val.configure(text=str(value)))


class PhaseToggle(ctk.CTkFrame):
    """Fila de control de fase individual."""

    def __init__(self, master, phase_id: str, label: str,
                 description: str, enabled: bool = True, **kwargs):
        super().__init__(master, fg_color="transparent", **kwargs)
        self.phase_id = phase_id
        self.var = ctk.BooleanVar(value=enabled)

        self.columnconfigure(1, weight=1)

        self._cb = ctk.CTkCheckBox(
            self, text="", variable=self.var,
            width=20, height=20,
            fg_color="#00FF41", hover_color="#00CC33",
            border_color="#333333", border_width=2,
            checkmark_color="#0D0D0D",
        )
        self._cb.grid(row=0, column=0, padx=(4, 8), sticky="w")

        label_frame = ctk.CTkFrame(self, fg_color="transparent")
        label_frame.grid(row=0, column=1, sticky="ew")

        ctk.CTkLabel(
            label_frame, text=label,
            font=ctk.CTkFont(family="Courier New", size=12, weight="bold"),
            text_color="#CCCCCC", anchor="w",
        ).pack(anchor="w")

        ctk.CTkLabel(
            label_frame, text=description,
            font=ctk.CTkFont(family="Courier New", size=9),
            text_color="#555555", anchor="w",
        ).pack(anchor="w")

    @property
    def enabled(self) -> bool:
        return self.var.get()


class LeftPanel(ctk.CTkFrame):
    """
    Panel izquierdo de OVERLORD.
    Contiene: configuración de target, toggles de fases,
    estadísticas en tiempo real y el botón ENGAGE/ABORT.
    """

    def __init__(self, master,
                 on_engage: Callable[[], None],
                 on_abort:  Callable[[], None],
                 on_clear:  Callable[[], None],
                 **kwargs):
        super().__init__(master, fg_color="#0D0D0D",
                         corner_radius=0, width=280, **kwargs)
        self.on_engage = on_engage
        self.on_abort  = on_abort
        self.on_clear  = on_clear

        self._build()

    def _build(self):
        self.pack_propagate(False)

        # ── Logo ─────────────────────────────────────────────────────────────
        logo_frame = ctk.CTkFrame(self, fg_color="#0A0A0A", corner_radius=0, height=70)
        logo_frame.pack(fill="x")
        logo_frame.pack_propagate(False)

        ctk.CTkLabel(
            logo_frame, text="◈ OVERLORD",
            font=ctk.CTkFont(family="Courier New", size=20, weight="bold"),
            text_color="#00FF41",
        ).pack(pady=(12, 0))
        ctk.CTkLabel(
            logo_frame, text="OFFENSIVE RECON PIPELINE v1.0",
            font=ctk.CTkFont(family="Courier New", size=8),
            text_color="#334433",
        ).pack()

        # ── Separador ────────────────────────────────────────────────────────
        ctk.CTkFrame(self, fg_color="#1A2A1A", height=1).pack(fill="x")

        # ── Target input ─────────────────────────────────────────────────────
        t_frame = ctk.CTkFrame(self, fg_color="transparent")
        t_frame.pack(fill="x", padx=12, pady=(14, 0))

        ctk.CTkLabel(
            t_frame, text="TARGET",
            font=ctk.CTkFont(family="Courier New", size=9, weight="bold"),
            text_color="#666666",
        ).pack(anchor="w")

        self.target_entry = ctk.CTkEntry(
            t_frame,
            placeholder_text="target.com",
            font=ctk.CTkFont(family="Courier New", size=13),
            fg_color="#111111",
            border_color="#1A3A1A",
            border_width=1,
            text_color="#00FF41",
            placeholder_text_color="#334433",
            height=36,
        )
        self.target_entry.pack(fill="x", pady=(4, 0))

        # ── Opciones de Recon ─────────────────────────────────────────────────
        opt_frame = ctk.CTkFrame(self, fg_color="transparent")
        opt_frame.pack(fill="x", padx=12, pady=(10, 0))
        opt_frame.columnconfigure((0, 1), weight=1)

        ctk.CTkLabel(
            opt_frame, text="RECON ENGINE",
            font=ctk.CTkFont(family="Courier New", size=9, weight="bold"),
            text_color="#666666",
        ).grid(row=0, column=0, columnspan=2, sticky="w", pady=(0, 4))

        self.recon_tool = ctk.StringVar(value="subfinder")
        for i, (val, txt) in enumerate([("subfinder", "Subfinder"), ("amass", "Amass")]):
            ctk.CTkRadioButton(
                opt_frame, text=txt, variable=self.recon_tool, value=val,
                font=ctk.CTkFont(family="Courier New", size=10),
                fg_color="#00FF41", hover_color="#00CC33",
                text_color="#AAAAAA",
            ).grid(row=1, column=i, sticky="w")

        # ── Pipeline Toggles ──────────────────────────────────────────────────
        ctk.CTkLabel(
            self, text="  PIPELINE STAGES",
            font=ctk.CTkFont(family="Courier New", size=9, weight="bold"),
            text_color="#666666", anchor="w",
        ).pack(fill="x", padx=12, pady=(16, 4))

        phases_data = [
            ("recon",   "01 │ RECON",   "Subfinder / Amass",            True),
            ("probe",   "02 │ PROBE",   "HTTPX → Hosts vivos",          True),
            ("infra",   "03 │ INFRA",   "Masscan + Nmap (root reqs.)",   False),
            ("exploit", "04 │ EXPLOIT", "Nuclei CVEs + FFUF Fuzzing",    True),
        ]

        self._phases: dict[str, PhaseToggle] = {}
        for pid, label, desc, enabled in phases_data:
            pt = PhaseToggle(self, pid, label, desc, enabled)
            pt.pack(fill="x", padx=8, pady=2)
            self._phases[pid] = pt

        # Flecha de pipeline
        ctk.CTkLabel(
            self, text="      ↓  ↓  ↓  ↓",
            font=ctk.CTkFont(family="Courier New", size=10),
            text_color="#1A3A1A",
        ).pack(pady=(4, 0))

        # ── Configuración extra ───────────────────────────────────────────────
        ctk.CTkLabel(
            self, text="  WORDLIST (FFUF)",
            font=ctk.CTkFont(family="Courier New", size=9, weight="bold"),
            text_color="#666666", anchor="w",
        ).pack(fill="x", padx=12, pady=(12, 2))

        self.wordlist_entry = ctk.CTkEntry(
            self,
            placeholder_text="/usr/share/wordlists/dirb/common.txt",
            font=ctk.CTkFont(family="Courier New", size=9),
            fg_color="#111111", border_color="#1A2A1A",
            text_color="#888888", height=28,
        )
        self.wordlist_entry.pack(fill="x", padx=12)

        ctk.CTkLabel(
            self, text="  NUCLEI TAGS",
            font=ctk.CTkFont(family="Courier New", size=9, weight="bold"),
            text_color="#666666", anchor="w",
        ).pack(fill="x", padx=12, pady=(8, 2))

        self.nuclei_tags = ctk.CTkEntry(
            self,
            placeholder_text="cves,misconfig,exposed-panels",
            font=ctk.CTkFont(family="Courier New", size=9),
            fg_color="#111111", border_color="#1A2A1A",
            text_color="#888888", height=28,
        )
        self.nuclei_tags.pack(fill="x", padx=12)

        # ── Stats ─────────────────────────────────────────────────────────────
        ctk.CTkLabel(
            self, text="  INTEL STATS",
            font=ctk.CTkFont(family="Courier New", size=9, weight="bold"),
            text_color="#666666", anchor="w",
        ).pack(fill="x", padx=12, pady=(16, 6))

        stats_grid = ctk.CTkFrame(self, fg_color="transparent")
        stats_grid.pack(fill="x", padx=8)
        stats_grid.columnconfigure((0, 1, 2), weight=1)

        self.stat_subs   = StatCard(stats_grid, "SUBS",    "#00FF41")
        self.stat_hosts  = StatCard(stats_grid, "HOSTS",   "#00BFFF")
        self.stat_ports  = StatCard(stats_grid, "PORTS",   "#FFD700")
        self.stat_subs.grid( row=0, column=0, padx=2, pady=2, sticky="ew")
        self.stat_hosts.grid(row=0, column=1, padx=2, pady=2, sticky="ew")
        self.stat_ports.grid(row=0, column=2, padx=2, pady=2, sticky="ew")

        self.stat_crits  = StatCard(stats_grid, "CRITICAL", "#FF3333")
        self.stat_highs  = StatCard(stats_grid, "HIGH",     "#FF8C00")
        self.stat_finds  = StatCard(stats_grid, "TOTAL",    "#CC88FF")
        self.stat_crits.grid(row=1, column=0, padx=2, pady=2, sticky="ew")
        self.stat_highs.grid(row=1, column=1, padx=2, pady=2, sticky="ew")
        self.stat_finds.grid(row=1, column=2, padx=2, pady=2, sticky="ew")

        # ── Spacer ────────────────────────────────────────────────────────────
        ctk.CTkFrame(self, fg_color="transparent").pack(fill="both", expand=True)

        # ── Botones de acción ─────────────────────────────────────────────────
        btn_frame = ctk.CTkFrame(self, fg_color="#0A0A0A", corner_radius=0)
        btn_frame.pack(fill="x", pady=(0, 0))

        self.engage_btn = ctk.CTkButton(
            btn_frame,
            text="⚡  ENGAGE",
            font=ctk.CTkFont(family="Courier New", size=15, weight="bold"),
            fg_color="#003300",
            hover_color="#005500",
            text_color="#00FF41",
            border_color="#00FF41",
            border_width=1,
            height=50,
            corner_radius=4,
            command=self.on_engage,
        )
        self.engage_btn.pack(fill="x", padx=10, pady=(10, 4))

        bottom_row = ctk.CTkFrame(btn_frame, fg_color="transparent")
        bottom_row.pack(fill="x", padx=10, pady=(0, 10))
        bottom_row.columnconfigure((0, 1), weight=1)

        self.abort_btn = ctk.CTkButton(
            bottom_row, text="■ ABORT",
            font=ctk.CTkFont(family="Courier New", size=11, weight="bold"),
            fg_color="#330000", hover_color="#550000",
            text_color="#FF3333", border_color="#FF3333", border_width=1,
            height=32, corner_radius=4,
            command=self.on_abort,
            state="disabled",
        )
        self.abort_btn.grid(row=0, column=0, padx=(0, 2), sticky="ew")

        ctk.CTkButton(
            bottom_row, text="⊘ CLEAR",
            font=ctk.CTkFont(family="Courier New", size=11),
            fg_color="#1A1A1A", hover_color="#2A2A2A",
            text_color="#666666", border_color="#333333", border_width=1,
            height=32, corner_radius=4,
            command=self.on_clear,
        ).grid(row=0, column=1, padx=(2, 0), sticky="ew")

    # ── API Pública ───────────────────────────────────────────────────────────

    @property
    def target(self) -> str:
        return self.target_entry.get().strip()

    @property
    def phases(self) -> dict[str, bool]:
        return {pid: pt.enabled for pid, pt in self._phases.items()}

    @property
    def extra_config(self) -> dict:
        return {
            "recon_tool":   self.recon_tool.get(),
            "wordlist":     self.wordlist_entry.get().strip() or None,
            "nuclei_tags":  self.nuclei_tags.get().strip() or None,
        }

    def set_running(self, running: bool):
        state_engage = "disabled" if running else "normal"
        state_abort  = "normal" if running else "disabled"
        self.engage_btn.after(0, lambda: self.engage_btn.configure(state=state_engage))
        self.abort_btn.after( 0, lambda: self.abort_btn.configure(state=state_abort))

    def update_stats(self, stats: dict):
        self.stat_subs.set( stats.get("subdomains", 0))
        self.stat_hosts.set(stats.get("hosts", 0))
        self.stat_ports.set(stats.get("ports", 0))
        self.stat_crits.set(stats.get("critical", 0))
        self.stat_highs.set(stats.get("high", 0))
        self.stat_finds.set(stats.get("findings", 0))
