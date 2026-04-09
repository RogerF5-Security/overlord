"""
OVERLORD :: Pipeline Orchestrator
Orquesta las 4 fases del pipeline de reconocimiento y explotación.
Alimenta datos de una fase a la siguiente mediante la base de datos.
"""
import asyncio
import re
import json
from typing import Callable, Awaitable, Optional
from dataclasses import dataclass, field

from .db import OverlordDB
from .runner import ProcessRunner


# ─── Evento del pipeline ──────────────────────────────────────────────────────

@dataclass
class PipelineEvent:
    phase: str          # "recon" | "probe" | "infra" | "exploit"
    tool:  str          # "subfinder" | "httpx" | ...
    line:  str          # línea raw de stdout/stderr
    level: str = "info" # "info" | "warn" | "error" | "critical" | "high"
    data:  dict = field(default_factory=dict)  # datos estructurados extraídos


EventCallback = Callable[[PipelineEvent], Awaitable[None]]


# ─── Configuración de comandos ────────────────────────────────────────────────

class ToolConfig:
    # Wordlists comunes en Kali
    WORDLIST_DIRS    = "/usr/share/wordlists/dirb/common.txt"
    WORDLIST_PARAMS  = "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt"
    NUCLEI_TEMPLATES = "~/nuclei-templates"

    @staticmethod
    def subfinder(target: str, use_all: bool = True) -> str:
        flags = "-all" if use_all else ""
        return f"subfinder -d {target} {flags} -silent -no-color"

    @staticmethod
    def amass(target: str) -> str:
        return f"amass enum -passive -d {target} -silent"

    @staticmethod
    def httpx(hosts_file: str) -> str:
        return (
            f"httpx -l {hosts_file} -silent -no-color "
            f"-status-code -title -tech-detect -follow-redirects -timeout 10"
        )

    @staticmethod
    def httpx_stdin() -> str:
        return (
            "httpx -silent -no-color "
            "-status-code -title -tech-detect -follow-redirects -timeout 10"
        )

    @staticmethod
    def masscan(targets_file: str, rate: int = 10000) -> str:
        # Requiere root; adaptar rate según el entorno
        return f"masscan -iL {targets_file} -p1-65535 --rate={rate} --open"

    @staticmethod
    def nmap_service(host: str, port: int) -> str:
        return f"nmap -sV -sC -p{port} --open -T4 -Pn {host}"

    @staticmethod
    def nuclei(hosts_file: str, tags: str = "cves,misconfig,exposed-panels,takeovers") -> str:
        return (
            f"nuclei -l {hosts_file} -tags {tags} "
            f"-severity critical,high,medium -no-color -silent"
        )

    @staticmethod
    def ffuf(url: str, wordlist: str = None) -> str:
        wl = wordlist or ToolConfig.WORDLIST_DIRS
        return (
            f"ffuf -u {url}/FUZZ -w {wl} "
            f"-mc 200,204,301,302,307,401,403 -t 50 -timeout 10 -noninteractive"
        )


# ─── Parsers de salida ────────────────────────────────────────────────────────

class OutputParser:

    # httpx: "admin.target.com [200] [Admin Panel] [Nginx,PHP]"
    HTTPX_RE = re.compile(
        r"^(https?://\S+)\s+\[(\d{3})\](?:\s+\[([^\]]*)\])?(?:\s+\[([^\]]*)\])?",
        re.IGNORECASE
    )

    # masscan: "Discovered open port 8080/tcp on 192.168.1.1"
    MASSCAN_RE = re.compile(
        r"Discovered open port (\d+)/(\w+) on ([\d.]+)"
    )

    # nuclei: "[critical] [cves/CVE-2023-XXXX] [http] target.com/path"
    NUCLEI_RE = re.compile(
        r"\[(\w+)\]\s+\[([^\]]+)\]\s+\[([^\]]+)\]\s+(\S+)"
    )

    # ffuf: path [status] [size]
    FFUF_RE = re.compile(
        r"^(\S+)\s+\[Status: (\d+),\s+Size: (\d+)"
    )

    # nmap service: "8080/tcp open  http-proxy nginx 1.24.0"
    NMAP_SVC_RE = re.compile(
        r"^(\d+)/(\w+)\s+open\s+(\S+)(?:\s+(.+))?$"
    )

    @classmethod
    def parse_httpx(cls, line: str) -> Optional[dict]:
        m = cls.HTTPX_RE.match(line.strip())
        if not m:
            return None
        host, code, title, techs = m.groups()
        return {
            "host":         host,
            "status_code":  int(code),
            "title":        title or "",
            "technologies": techs or "",
        }

    @classmethod
    def parse_masscan(cls, line: str) -> Optional[dict]:
        m = cls.MASSCAN_RE.search(line)
        if not m:
            return None
        port, proto, ip = m.groups()
        return {"host": ip, "port": int(port), "protocol": proto}

    @classmethod
    def parse_nuclei(cls, line: str) -> Optional[dict]:
        m = cls.NUCLEI_RE.search(line)
        if not m:
            return None
        severity, template, proto, target = m.groups()
        return {
            "severity": severity.upper(),
            "template": template,
            "protocol": proto,
            "target":   target,
            "name":     template.split("/")[-1],
        }

    @classmethod
    def parse_ffuf(cls, line: str) -> Optional[dict]:
        m = cls.FFUF_RE.match(line.strip())
        if not m:
            return None
        path, status, size = m.groups()
        return {"path": path, "status_code": int(status), "size": size}

    @classmethod
    def parse_nmap_service(cls, line: str) -> Optional[dict]:
        m = cls.NMAP_SVC_RE.match(line.strip())
        if not m:
            return None
        port, proto, svc, ver = m.groups()
        return {"port": int(port), "protocol": proto,
                "service": svc, "version": (ver or "").strip()}


# ─── Orquestador Principal ────────────────────────────────────────────────────

class OverlordPipeline:

    def __init__(
        self,
        target: str,
        db: OverlordDB,
        event_cb: EventCallback,
        phases: Optional[dict[str, bool]] = None,
        config: Optional[dict] = None,
    ):
        self.target    = target
        self.db        = db
        self.event_cb  = event_cb
        self.runner    = ProcessRunner()
        self.session_id: int = 0
        self._abort    = asyncio.Event()
        self.parser    = OutputParser()

        # Fases habilitadas por defecto
        self.phases = phases or {
            "recon":   True,
            "probe":   True,
            "infra":   False,
            "exploit": True,
        }

        # Config extra (wordlists, templates, etc.)
        self.config = config or {}

    # ── API pública ───────────────────────────────────────────────────────────

    async def run(self):
        """Punto de entrada del pipeline completo."""
        self.session_id = self.db.new_session(self.target)
        self._abort.clear()

        try:
            if self.phases.get("recon") and not self._abort.is_set():
                await self._phase_recon()

            if self.phases.get("probe") and not self._abort.is_set():
                await self._phase_probe()

            if self.phases.get("infra") and not self._abort.is_set():
                await self._phase_infra()

            if self.phases.get("exploit") and not self._abort.is_set():
                await self._phase_exploit()

        finally:
            self.db.close_session(self.session_id)

    def abort(self):
        """Señala abort; mata todos los subprocesos activos."""
        self._abort.set()
        self.runner.kill_all()

    # ── Fase 1: Reconocimiento ────────────────────────────────────────────────

    async def _phase_recon(self):
        await self._emit("recon", "system", "▶ FASE 1 :: Reconocimiento de Superficie", "info")

        tool_pref = self.config.get("recon_tool", "subfinder")
        if tool_pref == "amass":
            cmd = ToolConfig.amass(self.target)
            tool = "amass"
        else:
            cmd = ToolConfig.subfinder(self.target)
            tool = "subfinder"

        await self._emit("recon", tool, f"CMD: {cmd}", "info")

        async def on_line(line: str, stream: str):
            if self._abort.is_set():
                return
            sub = line.strip()
            if not sub or sub.startswith("["):
                await self._emit("recon", tool, line, "info")
                return
            self.db.add_subdomain(self.session_id, sub)
            await self._emit("recon", tool, sub, "info", {"subdomain": sub})

        await self.runner.run(f"recon_{tool}", cmd, on_line)

        count = len(self.db.get_subdomains(self.session_id))
        await self._emit("recon", "system", f"✔ Fase 1 completada → {count} subdominios", "info")

    # ── Fase 2: Probing / Host vivos ─────────────────────────────────────────

    async def _phase_probe(self):
        await self._emit("probe", "system", "▶ FASE 2 :: Resolución y Probing", "info")

        subdomains = self.db.get_subdomains(self.session_id)
        if not subdomains:
            await self._emit("probe", "system", "⚠ Sin subdominios. Usando target raíz.", "warn")
            subdomains = [self.target]

        # Escribir lista temporal
        tmp_file = f"/tmp/overlord_subs_{self.session_id}.txt"
        with open(tmp_file, "w") as f:
            f.write("\n".join(subdomains))

        cmd = ToolConfig.httpx(tmp_file)
        await self._emit("probe", "httpx", f"CMD: {cmd}", "info")

        async def on_line(line: str, stream: str):
            if self._abort.is_set():
                return
            await self._emit("probe", "httpx", line, "info")
            parsed = OutputParser.parse_httpx(line)
            if parsed:
                self.db.add_host(
                    self.session_id,
                    parsed["host"],
                    parsed["status_code"],
                    parsed["title"],
                    parsed["technologies"],
                )

        await self.runner.run("probe_httpx", cmd, on_line)

        count = len(self.db.get_hosts(self.session_id))
        await self._emit("probe", "system", f"✔ Fase 2 completada → {count} hosts vivos", "info")

    # ── Fase 3: Escaneo de Infraestructura ───────────────────────────────────

    async def _phase_infra(self):
        await self._emit("infra", "system", "▶ FASE 3 :: Escaneo de Infraestructura", "info")

        hosts = self.db.get_hosts(self.session_id)
        if not hosts:
            await self._emit("infra", "system", "⚠ Sin hosts vivos para escanear.", "warn")
            return

        # Extraer IPs/hostnames para masscan
        host_list = [h["host"].replace("https://", "").replace("http://", "").split("/")[0]
                     for h in hosts]
        tmp_file = f"/tmp/overlord_hosts_{self.session_id}.txt"
        with open(tmp_file, "w") as f:
            f.write("\n".join(set(host_list)))

        rate = self.config.get("masscan_rate", 5000)
        cmd = ToolConfig.masscan(tmp_file, rate)
        await self._emit("infra", "masscan", f"CMD: {cmd}", "info")

        open_ports: dict[str, list[int]] = {}

        async def on_masscan_line(line: str, stream: str):
            if self._abort.is_set():
                return
            await self._emit("infra", "masscan", line, "info")
            parsed = OutputParser.parse_masscan(line)
            if parsed:
                h, p, proto = parsed["host"], parsed["port"], parsed["protocol"]
                open_ports.setdefault(h, []).append(p)
                self.db.add_port(self.session_id, h, p, proto)

        await self.runner.run("infra_masscan", cmd, on_masscan_line)

        # Nmap service detection por puerto encontrado
        nmap_tasks = []
        for host, ports in open_ports.items():
            for port in ports:
                nmap_tasks.append(self._run_nmap_service(host, port))

        if nmap_tasks:
            await self._emit("infra", "nmap", f"Lanzando {len(nmap_tasks)} escaneos nmap...", "info")
            await asyncio.gather(*nmap_tasks)

        count = len(self.db.get_ports(self.session_id))
        await self._emit("infra", "system", f"✔ Fase 3 completada → {count} puertos mapeados", "info")

    async def _run_nmap_service(self, host: str, port: int):
        cmd = ToolConfig.nmap_service(host, port)

        async def on_line(line: str, stream: str):
            if self._abort.is_set():
                return
            await self._emit("infra", "nmap", line, "info")
            parsed = OutputParser.parse_nmap_service(line)
            if parsed:
                self.db.add_port(
                    self.session_id, host, parsed["port"],
                    parsed["protocol"], parsed["service"], parsed["version"]
                )

        await self.runner.run(f"nmap_{host}_{port}", cmd, on_line)

    # ── Fase 4: Explotación Dirigida ─────────────────────────────────────────

    async def _phase_exploit(self):
        await self._emit("exploit", "system", "▶ FASE 4 :: Explotación y Fuzzing Dirigido", "info")

        hosts = self.db.get_hosts(self.session_id)
        if not hosts:
            await self._emit("exploit", "system", "⚠ Sin hosts vivos. Usando target raíz.", "warn")
            hosts = [{"host": f"https://{self.target}"}]

        host_list = [h["host"] for h in hosts]
        tmp_file  = f"/tmp/overlord_alive_{self.session_id}.txt"
        with open(tmp_file, "w") as f:
            f.write("\n".join(host_list))

        # Nuclei + FFUF en paralelo
        await asyncio.gather(
            self._run_nuclei(tmp_file),
            *[self._run_ffuf(h["host"]) for h in hosts[:5]],  # Top 5 para no saturar
        )

        findings = self.db.get_findings(self.session_id)
        crits    = sum(1 for f in findings if f["severity"] == "CRITICAL")
        highs    = sum(1 for f in findings if f["severity"] == "HIGH")
        await self._emit(
            "exploit", "system",
            f"✔ Fase 4 completada → {len(findings)} hallazgos "
            f"(CRITICAL: {crits} | HIGH: {highs})",
            "info"
        )

    async def _run_nuclei(self, hosts_file: str):
        tags = self.config.get("nuclei_tags", "cves,misconfig,exposed-panels,takeovers")
        cmd  = ToolConfig.nuclei(hosts_file, tags)
        await self._emit("exploit", "nuclei", f"CMD: {cmd}", "info")

        async def on_line(line: str, stream: str):
            if self._abort.is_set():
                return
            parsed = OutputParser.parse_nuclei(line)

            if parsed:
                sev = parsed["severity"]
                # Determinar nivel de alerta
                level = "critical" if sev == "CRITICAL" else \
                        "high"     if sev == "HIGH"     else "info"

                self.db.add_finding(
                    self.session_id,
                    parsed["target"],
                    "nuclei",
                    sev,
                    parsed["name"],
                    parsed["template"],
                    line.strip()
                )
                await self._emit("exploit", "nuclei", line, level, parsed)
            else:
                await self._emit("exploit", "nuclei", line, "info")

        await self.runner.run("exploit_nuclei", cmd, on_line)

    async def _run_ffuf(self, host: str):
        wordlist = self.config.get("wordlist", ToolConfig.WORDLIST_DIRS)
        cmd      = ToolConfig.ffuf(host, wordlist)
        await self._emit("exploit", "ffuf", f"CMD: {cmd}", "info")

        async def on_line(line: str, stream: str):
            if self._abort.is_set():
                return
            parsed = OutputParser.parse_ffuf(line)
            if parsed:
                self.db.add_directory(
                    self.session_id, host,
                    parsed["path"], parsed["status_code"], parsed["size"]
                )
                await self._emit("exploit", "ffuf", line, "info", parsed)
            else:
                await self._emit("exploit", "ffuf", line, "info")

        await self.runner.run(f"exploit_ffuf_{host}", cmd, on_line)

    # ── Utilidades ────────────────────────────────────────────────────────────

    async def _emit(self, phase: str, tool: str, line: str,
                    level: str = "info", data: Optional[dict] = None):
        ev = PipelineEvent(phase=phase, tool=tool, line=line,
                           level=level, data=data or {})
        await self.event_cb(ev)
