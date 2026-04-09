# PROJECT OVERLORD — Offensive Recon Pipeline

Orquestador GUI asíncrono para pruebas de penetración autorizadas.
Coordina un pipeline de 4 fases integrando herramientas nativas de Kali Linux.

---

## Arquitectura

```
overlord/
├── overlord.py              ← Entry point
└── overlord/
    ├── db.py                ← SQLite3: correlación de datos entre fases
    ├── runner.py            ← asyncio.create_subprocess_shell engine
    ├── pipeline.py          ← Orquestador de 4 fases + parsers de output
    └── gui/
        ├── app.py           ← Ventana principal + asyncio↔tkinter bridge
        ├── left_panel.py    ← Pipeline control + stats
        ├── center_panel.py  ← Consolas multiplexadas por fase
        ├── right_panel.py   ← Intelligence Board (findings + hosts)
        └── console.py       ← Widget de terminal embebida
```

## Stack Tecnológico

| Componente     | Tecnología                          |
|----------------|-------------------------------------|
| GUI            | CustomTkinter (dark theme)          |
| Motor async    | asyncio.create_subprocess_shell     |
| Base de datos  | SQLite3 (overlord.db)               |
| IPC            | queue.Queue (asyncio↔tkinter bridge)|

## Instalación

```bash
# 1. Dependencias Python
pip install customtkinter

# 2. Herramientas del pipeline (Kali Linux)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/ffuf/ffuf/v2@latest
sudo apt install masscan nmap amass -y

# 3. Templates de Nuclei
nuclei -update-templates

# 4. Lanzar OVERLORD
python overlord.py
```

## Pipeline de 4 Fases

```
TARGET ──→ [01 RECON] ──→ [02 PROBE] ──→ [03 INFRA] ──→ [04 EXPLOIT]
              │                │                │               │
           Subfinder         HTTPX           Masscan         Nuclei
           Amass         (hosts vivos)      Nmap -sV          FFUF
              │                │                │               │
              └────────────────┴────────────────┴───────→ SQLite DB
                                                          overlord.db
```

### Fase 1: RECON
- **Subfinder** o **Amass** en modo pasivo
- Captura subdominios línea por línea en tiempo real
- Almacena en tabla `subdomains`

### Fase 2: PROBE
- **HTTPX** recibe la lista de subdominios
- Detecta: status_code, title, tecnologías (Nginx, PHP, WordPress…)
- Filtra hosts vivos (200/301/302/403)
- Almacena en tabla `hosts`

### Fase 3: INFRA (requiere root para masscan)
- **Masscan** escaneo rápido de puertos completos
- Por cada puerto abierto → **Nmap -sV** para banner/versión
- Almacena en tabla `ports`

### Fase 4: EXPLOIT
- **Nuclei** con tags: cves, misconfig, exposed-panels, takeovers
- **FFUF** fuzzing de directorios en los primeros 5 hosts
- Hallazgos CRITICAL/HIGH → flash rojo en Intelligence Board
- Almacena en tabla `findings` y `directories`

## GUI Layout

```
┌─────────────────┬────────────────────────────┬──────────────────┐
│   LEFT PANEL    │      CENTER PANEL           │   RIGHT PANEL    │
│                 │                             │                  │
│ ◈ TARGET INPUT  │ [ALL][RECON][PROBE][EXPLOIT]│ ◈ LIVE HOSTS     │
│                 │                             │                  │
│ ○ Subfinder     │  ┌─────────────────────┐   │  host | code     │
│ ○ Amass         │  │ [CONSOLA EN TIEMPO  │   │  …               │
│                 │  │  REAL CON COLORES]  │   │                  │
│ [x] 01 RECON    │  │  ● stdout verde     │   │ ◈ FINDINGS BOARD │
│ [x] 02 PROBE    │  │  ● critical rojo    │   │                  │
│ [ ] 03 INFRA    │  │  ● warn amarillo    │   │  SEV|HOST|FIND   │
│ [x] 04 EXPLOIT  │  └─────────────────────┘   │  CRIT|api.target │
│                 │                             │  HIGH|admin.tgt  │
│ WORDLIST: …     │                             │                  │
│ NUCLEI TAGS: …  │                             │ ◈ PAYLOAD DETAIL │
│                 │                             │  [raw line]      │
│ SUBS HOSTS PORTS│                             │                  │
│  12   8    45   │                             │ [⬇JSON] [⬇CSV]   │
│ CRIT HIGH TOTAL │                             │                  │
│   2    5    18  │                             │                  │
│                 │                             │                  │
│ ⚡ ENGAGE        │                             │                  │
│ ■ABORT  ⊘CLEAR  │                             │                  │
└─────────────────┴────────────────────────────┴──────────────────┘
```

## Esquema de Base de Datos

```sql
sessions    → id, target, started, ended
subdomains  → session_id, subdomain, discovered
hosts       → session_id, host, status_code, title, technologies
ports       → session_id, host, port, protocol, service, version
findings    → session_id, host, tool, severity, name, description, payload, found_at
directories → session_id, host, path, status_code, size
```

## Exportación de Resultados

- **JSON**: Reporte completo estructurado para integración con otros sistemas
- **CSV**: Findings ordenados por severidad para documentación

## Notas de Seguridad

- Fase 3 (Masscan) requiere `sudo`; configurable vía checkbox
- El pipeline es totalmente documentable: cada comando ejecutado
  queda registrado en la consola con timestamp
- La base de datos `overlord.db` persiste entre sesiones
- Usar exclusivamente en entornos con autorización explícita por escrito
