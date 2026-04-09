"""
OVERLORD :: Async Subprocess Runner
Motor central de ejecución de herramientas vía asyncio.create_subprocess_shell.
Lee stdout/stderr línea por línea en tiempo real y los enruta a callbacks.
"""
import asyncio
import shlex
from typing import Callable, Awaitable, Optional

LineCallback = Callable[[str, str], Awaitable[None]]  # (line, stream) -> None


class ProcessRunner:
    """Ejecuta un comando shell de forma asíncrona, leyendo salida en tiempo real."""

    def __init__(self):
        self._procs: dict[str, asyncio.subprocess.Process] = {}

    async def run(
        self,
        tag: str,
        cmd: str,
        on_line: LineCallback,
        on_done: Optional[Callable[[int], Awaitable[None]]] = None,
        env: Optional[dict] = None,
    ) -> int:
        """
        Lanza `cmd` en un subproceso shell.
        Por cada línea de stdout llama on_line(line, 'stdout').
        Por cada línea de stderr llama on_line(line, 'stderr').
        Retorna el código de retorno del proceso.
        """
        proc = await asyncio.create_subprocess_shell(
            cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=env,
        )
        self._procs[tag] = proc

        async def drain_stream(stream: asyncio.StreamReader, label: str):
            while True:
                try:
                    raw = await stream.readline()
                except Exception:
                    break
                if not raw:
                    break
                line = raw.decode("utf-8", errors="replace").rstrip()
                if line:
                    await on_line(line, label)

        await asyncio.gather(
            drain_stream(proc.stdout, "stdout"),
            drain_stream(proc.stderr, "stderr"),
        )

        rc = await proc.wait()
        self._procs.pop(tag, None)

        if on_done:
            await on_done(rc)

        return rc

    async def run_and_collect(self, cmd: str) -> tuple[list[str], int]:
        """Versión simplificada: ejecuta y retorna (líneas_stdout, returncode)."""
        lines: list[str] = []

        async def collect(line: str, stream: str):
            if stream == "stdout":
                lines.append(line)

        rc = await self.run("_collect", cmd, collect)
        return lines, rc

    def kill(self, tag: str):
        """Mata un proceso por su tag."""
        proc = self._procs.get(tag)
        if proc and proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass

    def kill_all(self):
        for tag in list(self._procs.keys()):
            self.kill(tag)


class ToolChecker:
    """Verifica disponibilidad de herramientas en el sistema."""

    REQUIRED_TOOLS = {
        "subfinder": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
        "amass":     "apt install amass / go install",
        "httpx":     "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "masscan":   "apt install masscan",
        "nmap":      "apt install nmap",
        "nuclei":    "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "ffuf":      "go install github.com/ffuf/ffuf/v2@latest",
    }

    @staticmethod
    async def check(tool: str) -> bool:
        proc = await asyncio.create_subprocess_shell(
            f"which {shlex.quote(tool)}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        return proc.returncode == 0

    @classmethod
    async def check_all(cls) -> dict[str, bool]:
        results = {}
        tasks = {t: cls.check(t) for t in cls.REQUIRED_TOOLS}
        for tool, coro in tasks.items():
            results[tool] = await coro
        return results
