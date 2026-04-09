"""
OVERLORD :: Console Widget
Mini-terminal embebida en la GUI con colores por severidad y scroll automático.
"""
import tkinter as tk
import customtkinter as ctk
from datetime import datetime


SEVERITY_COLORS = {
    "critical": "#FF3333",
    "high":     "#FF8C00",
    "warn":     "#FFD700",
    "error":    "#FF4444",
    "info":     "#00FF41",   # Matrix green
    "muted":    "#666666",
    "cmd":      "#00BFFF",   # Cyan para comandos
    "system":   "#C0C0C0",   # Gris plata para mensajes del sistema
    "default":  "#00FF41",
}


class ConsoleWidget(ctk.CTkFrame):
    """
    Widget de consola con fondo negro, fuente monoespaciada y scroll.
    Soporta coloreado por severidad y timestamps opcionales.
    """

    MAX_LINES = 5000  # Límite para evitar consumo de memoria excesivo

    def __init__(self, master, title: str = "Console",
                 show_timestamps: bool = True, **kwargs):
        super().__init__(master, fg_color="#0A0A0A", corner_radius=6, **kwargs)
        self.show_timestamps = show_timestamps
        self._line_count = 0

        # ── Header ──────────────────────────────────────────────────────────
        self._header = ctk.CTkLabel(
            self, text=f"  ◈ {title.upper()}",
            font=ctk.CTkFont(family="Courier New", size=11, weight="bold"),
            text_color="#00FF41", fg_color="#111111",
            anchor="w", height=26,
        )
        self._header.pack(fill="x", pady=(0, 1))

        # ── Text area ────────────────────────────────────────────────────────
        self._text = tk.Text(
            self,
            bg="#0D0D0D",
            fg="#00FF41",
            insertbackground="#00FF41",
            selectbackground="#1A3A1A",
            font=("Courier New", 10),
            wrap=tk.WORD,
            relief="flat",
            padx=6,
            pady=4,
            state="disabled",
            border=0,
            highlightthickness=0,
            undo=False,
        )

        # Scrollbar
        self._scrollbar = ctk.CTkScrollbar(self, command=self._text.yview)
        self._text.configure(yscrollcommand=self._scrollbar.set)

        self._scrollbar.pack(side="right", fill="y")
        self._text.pack(side="left", fill="both", expand=True)

        # Configurar tags de color
        for level, color in SEVERITY_COLORS.items():
            self._text.tag_configure(level, foreground=color)
        self._text.tag_configure("bold", font=("Courier New", 10, "bold"))
        self._text.tag_configure(
            "critical",
            foreground=SEVERITY_COLORS["critical"],
            background="#330000",
            font=("Courier New", 10, "bold"),
        )

    def write(self, line: str, level: str = "info", tool: str = ""):
        """Escribe una línea en la consola desde cualquier hilo (thread-safe vía after)."""
        self._text.after(0, self._write_safe, line, level, tool)

    def _write_safe(self, line: str, level: str, tool: str):
        """Escritura real en el widget (debe ejecutarse en el hilo de tkinter)."""
        self._text.configure(state="normal")

        # Limitar líneas
        self._line_count += 1
        if self._line_count > self.MAX_LINES:
            self._text.delete("1.0", "500.0")
            self._line_count -= 500

        # Timestamp
        if self.show_timestamps:
            ts = datetime.now().strftime("%H:%M:%S")
            self._text.insert("end", f"[{ts}] ", "muted")

        # Tool prefix
        if tool:
            self._text.insert("end", f"[{tool:8s}] ", "cmd")

        # Línea coloreada
        color_tag = level if level in SEVERITY_COLORS else "default"
        self._text.insert("end", line + "\n", color_tag)

        self._text.configure(state="disabled")
        self._text.see("end")  # Auto-scroll

    def write_banner(self, text: str):
        """Escribe un banner destacado."""
        separator = "─" * 60
        self._text.after(0, lambda: [
            self._write_safe(separator, "muted", ""),
            self._write_safe(text, "system", ""),
            self._write_safe(separator, "muted", ""),
        ])

    def clear(self):
        self._text.after(0, self._clear_safe)

    def _clear_safe(self):
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._line_count = 0
        self._text.configure(state="disabled")

    def update_title(self, title: str, color: str = "#00FF41"):
        self._header.after(
            0,
            lambda: self._header.configure(
                text=f"  ◈ {title.upper()}", text_color=color
            )
        )
