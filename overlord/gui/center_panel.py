"""
OVERLORD :: Center Panel - Consolas Multiplexadas
Grid de consolas en tiempo real, una por fase/herramienta.
Usa tabs para separar las vistas: ALL | RECON | PROBE | INFRA | EXPLOIT
"""
import customtkinter as ctk
from .console import ConsoleWidget


PHASE_CONFIG = {
    "recon":   {"label": "01 RECON",   "color": "#00FF41", "tools": ["subfinder", "amass"]},
    "probe":   {"label": "02 PROBE",   "color": "#00BFFF", "tools": ["httpx"]},
    "infra":   {"label": "03 INFRA",   "color": "#FFD700", "tools": ["masscan", "nmap"]},
    "exploit": {"label": "04 EXPLOIT", "color": "#FF8C00", "tools": ["nuclei", "ffuf"]},
    "system":  {"label": "SYSTEM",     "color": "#C0C0C0", "tools": ["system"]},
}


class CenterPanel(ctk.CTkFrame):
    """
    Panel central con tab switcher y consolas multiplexadas.
    Consola "ALL" muestra todo el output consolidado.
    Consolas por fase muestran solo su output.
    """

    def __init__(self, master, **kwargs):
        super().__init__(master, fg_color="#0D0D0D", corner_radius=0, **kwargs)
        self._build()

    def _build(self):
        # ── Tab bar ───────────────────────────────────────────────────────────
        tab_bar = ctk.CTkFrame(self, fg_color="#0A0A0A", corner_radius=0, height=36)
        tab_bar.pack(fill="x")
        tab_bar.pack_propagate(False)

        # Status bar
        self._status_label = ctk.CTkLabel(
            tab_bar, text="● IDLE",
            font=ctk.CTkFont(family="Courier New", size=10, weight="bold"),
            text_color="#334433",
        )
        self._status_label.pack(side="right", padx=12)

        # Tab buttons
        self._tabs: dict[str, ctk.CTkButton] = {}
        self._active_tab = "all"

        tab_names = [
            ("all",    "ALL",        "#00FF41"),
            ("recon",  "01·RECON",   "#00FF41"),
            ("probe",  "02·PROBE",   "#00BFFF"),
            ("infra",  "03·INFRA",   "#FFD700"),
            ("exploit","04·EXPLOIT", "#FF8C00"),
        ]

        for tab_id, label, color in tab_names:
            btn = ctk.CTkButton(
                tab_bar, text=label,
                font=ctk.CTkFont(family="Courier New", size=10),
                width=90, height=28,
                fg_color="#111111" if tab_id != "all" else "#1A2A1A",
                hover_color="#1A3A1A",
                text_color=color if tab_id == "all" else "#555555",
                corner_radius=0,
                command=lambda t=tab_id: self._switch_tab(t),
            )
            btn.pack(side="left", padx=(2, 0))
            self._tabs[tab_id] = btn

        ctk.CTkFrame(self, fg_color="#1A2A1A", height=1).pack(fill="x")

        # ── Consola "ALL" ────────────────────────────────────────────────────
        self._consoles: dict[str, ConsoleWidget] = {}

        self._all_console = ConsoleWidget(self, title="ALL OUTPUT", show_timestamps=True)
        self._consoles["all"] = self._all_console
        self._all_console.pack(fill="both", expand=True, padx=4, pady=4)

        # ── Consolas por fase (ocultas inicialmente) ─────────────────────────
        for phase, cfg in PHASE_CONFIG.items():
            console = ConsoleWidget(self, title=cfg["label"], show_timestamps=True)
            self._consoles[phase] = console
            # No hacemos pack aún; se muestran al cambiar de tab

        # Mostrar "all" por defecto
        self._switch_tab("all")

    # ── API Pública ───────────────────────────────────────────────────────────

    def write(self, phase: str, tool: str, line: str, level: str = "info"):
        """Escribe en la consola de la fase correspondiente y en ALL."""
        # Consola específica de fase
        con = self._consoles.get(phase)
        if con:
            con.write(line, level, tool)

        # Consola ALL siempre recibe todo
        prefix_level = level if level != "info" else \
                       "cmd" if phase == "system" else "info"
        self._consoles["all"].write(line, prefix_level, f"{phase[:4]}:{tool[:6]}")

    def clear_all(self):
        for con in self._consoles.values():
            con.clear()

    def set_status(self, text: str, color: str = "#00FF41"):
        self._status_label.after(
            0,
            lambda: self._status_label.configure(text=text, text_color=color)
        )

    def mark_phase_active(self, phase: str):
        """Resalta el tab de la fase activa."""
        cfg = PHASE_CONFIG.get(phase, {})
        color = cfg.get("color", "#00FF41")
        tab = self._tabs.get(phase)
        if tab:
            tab.after(0, lambda: tab.configure(text_color=color, fg_color="#111111"))
        self.set_status(f"● {phase.upper()}", color)

    def mark_phase_done(self, phase: str):
        """Marca el tab de una fase completada."""
        tab = self._tabs.get(phase)
        if tab:
            tab.after(0, lambda: tab.configure(
                text_color="#00FF41",
                fg_color="#0A1A0A",
            ))

    # ── Tab switching ─────────────────────────────────────────────────────────

    def _switch_tab(self, tab_id: str):
        # Ocultar todos
        for con in self._consoles.values():
            con.pack_forget()

        # Mostrar el seleccionado
        self._consoles[tab_id].pack(fill="both", expand=True, padx=4, pady=4)

        # Actualizar botones
        for tid, btn in self._tabs.items():
            is_active = tid == tab_id
            cfg = PHASE_CONFIG.get(tid, {})
            color = cfg.get("color", "#00FF41") if is_active else "#555555"
            bg    = "#1A2A1A" if is_active else "#111111"
            btn.configure(fg_color=bg, text_color=color)

        self._active_tab = tab_id
