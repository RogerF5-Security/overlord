"""
OVERLORD :: Main Application
Ventana principal. Puente entre asyncio y tkinter.
Orquesta el pipeline y enruta eventos a la GUI.
"""
import asyncio
import threading
import queue
from datetime import datetime
from typing import Optional
import customtkinter as ctk
import tkinter as tk
from tkinter import messagebox

from ..db import OverlordDB
from ..pipeline import OverlordPipeline, PipelineEvent
from ..runner import ToolChecker

from .left_panel   import LeftPanel
from .center_panel import CenterPanel
from .right_panel  import RightPanel


# ── CustomTkinter global config ────────────────────────────────────────────────
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")


class OverlordApp(ctk.CTk):
    """
    Aplicación principal de OVERLORD.
    Arquitectura: asyncio corre en un hilo de background.
    La GUI vive en el hilo principal.
    Comunicación vía queue thread-safe + polling con after().
    """

    def __init__(self):
        super().__init__()
        self.title("◈ PROJECT OVERLORD :: Offensive Recon Pipeline")
        self.geometry("1400x860")
        self.minsize(1100, 700)
        self.configure(fg_color="#080808")

        # ── Estado ────────────────────────────────────────────────────────────
        self._db:        OverlordDB           = OverlordDB("overlord.db")
        self._pipeline:  Optional[OverlordPipeline] = None
        self._loop:      Optional[asyncio.AbstractEventLoop] = None
        self._thread:    Optional[threading.Thread] = None
        self._event_q:   queue.Queue = queue.Queue()
        self._running:   bool = False
        self._session_id: int = 0
        self._stats_counter = 0

        # ── Layout ────────────────────────────────────────────────────────────
        self._build_layout()

        # ── Iniciar loop asyncio ──────────────────────────────────────────────
        self._start_async_loop()

        # ── Polling de eventos ────────────────────────────────────────────────
        self._poll_events()

        # ── Verificar herramientas al inicio ──────────────────────────────────
        self.after(500, self._check_tools_async)

        # ── Cerrar limpio ─────────────────────────────────────────────────────
        self.protocol("WM_DELETE_WINDOW", self._on_close)

    # ── Build UI ──────────────────────────────────────────────────────────────

    def _build_layout(self):
        # Grid principal: left | center | right
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.left   = LeftPanel(
            self,
            on_engage=self._engage,
            on_abort=self._abort,
            on_clear=self._clear,
        )
        self.left.grid(row=0, column=0, sticky="nsw")

        # Separador vertical
        ctk.CTkFrame(self, fg_color="#1A2A1A", width=1).grid(
            row=0, column=1, sticky="ns"
        )

        self.center = CenterPanel(self)
        self.center.grid(row=0, column=2, sticky="nsew")
        self.grid_columnconfigure(2, weight=1)

        # Separador vertical
        ctk.CTkFrame(self, fg_color="#1A2A1A", width=1).grid(
            row=0, column=3, sticky="ns"
        )

        self.right  = RightPanel(self)
        self.right.grid(row=0, column=4, sticky="nse")

    # ── Asyncio bridge ────────────────────────────────────────────────────────

    def _start_async_loop(self):
        """Arranca el event loop de asyncio en un hilo daemon."""
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="overlord-async"
        )
        self._thread.start()

    def _run_loop(self):
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _submit(self, coro):
        """Envía una coroutine al loop de asyncio desde el hilo de tkinter."""
        return asyncio.run_coroutine_threadsafe(coro, self._loop)

    # ── Event queue polling ───────────────────────────────────────────────────

    def _poll_events(self):
        """Procesamos hasta 50 eventos de la queue por tick para no bloquear la GUI."""
        for _ in range(50):
            try:
                ev: PipelineEvent = self._event_q.get_nowait()
                self._handle_event(ev)
            except queue.Empty:
                break
        self.after(25, self._poll_events)  # Poll cada 25ms

    def _handle_event(self, ev: PipelineEvent):
        # Escribir en consola
        self.center.write(ev.phase, ev.tool, ev.line, ev.level)

        # Marcar fase activa
        if ev.tool == "system" and ev.line.startswith("▶"):
            self.center.mark_phase_active(ev.phase)

        # Fase completa
        if ev.tool == "system" and ev.line.startswith("✔"):
            self.center.mark_phase_done(ev.phase)

        # Pipeline finalizado
        if ev.phase == "_done":
            self._on_pipeline_done()
            return

        # Hallazgo crítico/alto: poblar intel board
        if ev.level in ("critical", "high") and ev.data:
            finding = {
                "host":     ev.data.get("target", ""),
                "severity": ev.data.get("severity", ev.level.upper()),
                "name":     ev.data.get("name", ""),
                "tool":     ev.tool,
                "found_at": datetime.now().isoformat(),
                "payload":  ev.line,
            }
            self.right.add_finding(finding)

            # Flash en rojo para críticos
            if ev.level == "critical":
                self.right.flash_critical()
                self.center.set_status("● CRITICAL FINDING!", "#FF3333")

        # Host vivo detectado
        if ev.phase == "probe" and ev.data and "host" in ev.data:
            self.right.add_host(ev.data)

        # Stats periódicas
        self._stats_counter += 1
        if self._stats_counter % 10 == 0 and self._session_id:
            self._update_stats()

    def _update_stats(self):
        if not self._session_id:
            return
        stats = self._db.stats(self._session_id)
        self.left.update_stats(stats)
        # Actualizar datos de reporte
        report = self._db.export_report(self._session_id)
        self.right.set_report_data(report)

    # ── Pipeline control ──────────────────────────────────────────────────────

    def _engage(self):
        target = self.left.target
        if not target:
            messagebox.showwarning(
                "TARGET REQUIRED",
                "Especifica un dominio objetivo antes de ejecutar.",
                parent=self,
            )
            return

        if self._running:
            return

        self._clear()
        self._running = True
        self.left.set_running(True)
        self.center.set_status("● RUNNING", "#00FF41")

        # Mostrar banner de inicio
        self.center._consoles["all"].write_banner(
            f"TARGET: {target}  ·  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        )

        phases = self.left.phases
        config = self.left.extra_config
        # Limpiar Nones del config
        config = {k: v for k, v in config.items() if v}

        self._pipeline = OverlordPipeline(
            target=target,
            db=self._db,
            event_cb=self._async_event_cb,
            phases=phases,
            config=config,
        )
        self._session_id = 0  # Se asignará en pipeline.run()

        self._submit(self._run_pipeline())

    async def _run_pipeline(self):
        try:
            await self._pipeline.run()
            self._session_id = self._pipeline.session_id
        except Exception as e:
            await self._async_event_cb(PipelineEvent(
                phase="system", tool="error",
                line=f"ERROR FATAL: {e}", level="error"
            ))
        finally:
            # Señal de finalización al hilo de tkinter
            await self._async_event_cb(PipelineEvent(
                phase="_done", tool="system", line="PIPELINE COMPLETE"
            ))

    async def _async_event_cb(self, ev: PipelineEvent):
        """Callback del pipeline: enruta el evento a la queue (thread-safe)."""
        self._event_q.put_nowait(ev)

    def _on_pipeline_done(self):
        self._running = False
        self.left.set_running(False)
        self.center.set_status("● COMPLETE", "#00FF41")

        # Stats finales
        if self._pipeline and self._pipeline.session_id:
            self._session_id = self._pipeline.session_id
            self._update_stats()

        self.center.write(
            "system", "overlord",
            "══════════════════════ PIPELINE COMPLETE ══════════════════════",
            "system"
        )

    def _abort(self):
        if self._pipeline and self._running:
            self._pipeline.abort()
            self._running = False
            self.left.set_running(False)
            self.center.set_status("● ABORTED", "#FF3333")
            self.center.write("system", "overlord", "■ PIPELINE ABORTED BY USER", "error")

    def _clear(self):
        self.center.clear_all()
        self.right.clear()
        self.left.update_stats({})
        self.center.set_status("● IDLE", "#334433")
        # Reset tab styles
        for tab in self.center._tabs.values():
            tab.configure(text_color="#555555", fg_color="#111111")
        if "all" in self.center._tabs:
            self.center._tabs["all"].configure(
                text_color="#00FF41", fg_color="#1A2A1A"
            )

    # ── Tool checker ──────────────────────────────────────────────────────────

    def _check_tools_async(self):
        self._submit(self._check_tools())

    async def _check_tools(self):
        results = await ToolChecker.check_all()
        missing = [t for t, ok in results.items() if not ok]
        available = [t for t, ok in results.items() if ok]

        for t in available:
            await self._async_event_cb(PipelineEvent(
                phase="system", tool="checker",
                line=f"[OK]  {t}", level="info"
            ))
        for t in missing:
            install = ToolChecker.REQUIRED_TOOLS.get(t, "")
            await self._async_event_cb(PipelineEvent(
                phase="system", tool="checker",
                line=f"[MISSING] {t} → {install}", level="warn"
            ))

    # ── Close ─────────────────────────────────────────────────────────────────

    def _on_close(self):
        if self._running:
            if not messagebox.askyesno(
                "Pipeline activo",
                "Hay un pipeline corriendo. ¿Abortar y salir?",
                parent=self,
            ):
                return
            self._abort()

        if self._loop and self._loop.is_running():
            self._loop.call_soon_threadsafe(self._loop.stop)

        self.destroy()


def launch():
    app = OverlordApp()
    app.mainloop()
