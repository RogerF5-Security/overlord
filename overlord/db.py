"""
OVERLORD :: Database Layer
SQLite3 para correlación de datos entre fases del pipeline.
"""
import sqlite3
import threading
from datetime import datetime
from typing import Optional


class OverlordDB:
    def __init__(self, path: str = "overlord.db"):
        self.path = path
        self._lock = threading.Lock()
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        with self._lock:
            conn = self._connect()
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id      INTEGER PRIMARY KEY AUTOINCREMENT,
                    target  TEXT NOT NULL,
                    started TEXT NOT NULL,
                    ended   TEXT
                );

                CREATE TABLE IF NOT EXISTS subdomains (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id  INTEGER NOT NULL,
                    subdomain   TEXT NOT NULL,
                    discovered  TEXT NOT NULL,
                    UNIQUE(session_id, subdomain)
                );

                CREATE TABLE IF NOT EXISTS hosts (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id  INTEGER NOT NULL,
                    host        TEXT NOT NULL,
                    status_code INTEGER,
                    title       TEXT,
                    technologies TEXT,
                    alive       INTEGER DEFAULT 1,
                    UNIQUE(session_id, host)
                );

                CREATE TABLE IF NOT EXISTS ports (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id  INTEGER NOT NULL,
                    host        TEXT NOT NULL,
                    port        INTEGER NOT NULL,
                    protocol    TEXT,
                    service     TEXT,
                    version     TEXT,
                    UNIQUE(session_id, host, port)
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id  INTEGER NOT NULL,
                    host        TEXT NOT NULL,
                    tool        TEXT NOT NULL,
                    severity    TEXT NOT NULL,
                    name        TEXT NOT NULL,
                    description TEXT,
                    payload     TEXT,
                    found_at    TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS directories (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id  INTEGER NOT NULL,
                    host        TEXT NOT NULL,
                    path        TEXT NOT NULL,
                    status_code INTEGER,
                    size        TEXT,
                    UNIQUE(session_id, host, path)
                );
            """)
            conn.commit()
            conn.close()

    def new_session(self, target: str) -> int:
        with self._lock:
            conn = self._connect()
            cur = conn.execute(
                "INSERT INTO sessions (target, started) VALUES (?, ?)",
                (target, datetime.now().isoformat())
            )
            conn.commit()
            sid = cur.lastrowid
            conn.close()
            return sid

    def close_session(self, session_id: int):
        with self._lock:
            conn = self._connect()
            conn.execute(
                "UPDATE sessions SET ended=? WHERE id=?",
                (datetime.now().isoformat(), session_id)
            )
            conn.commit()
            conn.close()

    def add_subdomain(self, session_id: int, subdomain: str):
        with self._lock:
            conn = self._connect()
            conn.execute(
                "INSERT OR IGNORE INTO subdomains (session_id, subdomain, discovered) VALUES (?,?,?)",
                (session_id, subdomain.strip(), datetime.now().isoformat())
            )
            conn.commit()
            conn.close()

    def get_subdomains(self, session_id: int) -> list[str]:
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT subdomain FROM subdomains WHERE session_id=?", (session_id,)
            ).fetchall()
            conn.close()
            return [r["subdomain"] for r in rows]

    def add_host(self, session_id: int, host: str, status_code: Optional[int] = None,
                 title: str = "", technologies: str = ""):
        with self._lock:
            conn = self._connect()
            conn.execute("""
                INSERT INTO hosts (session_id, host, status_code, title, technologies)
                VALUES (?,?,?,?,?)
                ON CONFLICT(session_id, host) DO UPDATE SET
                    status_code=excluded.status_code,
                    title=excluded.title,
                    technologies=excluded.technologies
            """, (session_id, host, status_code, title, technologies))
            conn.commit()
            conn.close()

    def get_hosts(self, session_id: int) -> list[dict]:
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM hosts WHERE session_id=? AND alive=1", (session_id,)
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]

    def add_port(self, session_id: int, host: str, port: int,
                 protocol: str = "tcp", service: str = "", version: str = ""):
        with self._lock:
            conn = self._connect()
            conn.execute("""
                INSERT INTO ports (session_id, host, port, protocol, service, version)
                VALUES (?,?,?,?,?,?)
                ON CONFLICT(session_id, host, port) DO UPDATE SET
                    service=excluded.service,
                    version=excluded.version
            """, (session_id, host, port, protocol, service, version))
            conn.commit()
            conn.close()

    def get_ports(self, session_id: int) -> list[dict]:
        with self._lock:
            conn = self._connect()
            rows = conn.execute(
                "SELECT * FROM ports WHERE session_id=?", (session_id,)
            ).fetchall()
            conn.close()
            return [dict(r) for r in rows]

    def add_finding(self, session_id: int, host: str, tool: str,
                    severity: str, name: str, description: str = "", payload: str = ""):
        with self._lock:
            conn = self._connect()
            conn.execute("""
                INSERT INTO findings
                    (session_id, host, tool, severity, name, description, payload, found_at)
                VALUES (?,?,?,?,?,?,?,?)
            """, (session_id, host, tool, severity.upper(), name, description,
                  payload, datetime.now().isoformat()))
            conn.commit()
            conn.close()

    def get_findings(self, session_id: int) -> list[dict]:
        with self._lock:
            conn = self._connect()
            rows = conn.execute("""
                SELECT * FROM findings WHERE session_id=?
                ORDER BY CASE severity
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH'     THEN 2
                    WHEN 'MEDIUM'   THEN 3
                    WHEN 'LOW'      THEN 4
                    ELSE 5
                END, found_at DESC
            """, (session_id,)).fetchall()
            conn.close()
            return [dict(r) for r in rows]

    def add_directory(self, session_id: int, host: str, path: str,
                      status_code: int = 200, size: str = ""):
        with self._lock:
            conn = self._connect()
            conn.execute("""
                INSERT OR IGNORE INTO directories
                    (session_id, host, path, status_code, size)
                VALUES (?,?,?,?,?)
            """, (session_id, host, path, status_code, size))
            conn.commit()
            conn.close()

    def stats(self, session_id: int) -> dict:
        with self._lock:
            conn = self._connect()
            stats = {
                "subdomains":  conn.execute("SELECT COUNT(*) FROM subdomains WHERE session_id=?", (session_id,)).fetchone()[0],
                "hosts":       conn.execute("SELECT COUNT(*) FROM hosts WHERE session_id=? AND alive=1", (session_id,)).fetchone()[0],
                "ports":       conn.execute("SELECT COUNT(*) FROM ports WHERE session_id=?", (session_id,)).fetchone()[0],
                "findings":    conn.execute("SELECT COUNT(*) FROM findings WHERE session_id=?", (session_id,)).fetchone()[0],
                "critical":    conn.execute("SELECT COUNT(*) FROM findings WHERE session_id=? AND severity='CRITICAL'", (session_id,)).fetchone()[0],
                "high":        conn.execute("SELECT COUNT(*) FROM findings WHERE session_id=? AND severity='HIGH'", (session_id,)).fetchone()[0],
                "directories": conn.execute("SELECT COUNT(*) FROM directories WHERE session_id=?", (session_id,)).fetchone()[0],
            }
            conn.close()
            return stats

    def export_report(self, session_id: int) -> dict:
        """Exporta todos los datos de la sesión para generación de reportes."""
        return {
            "subdomains":  self.get_subdomains(session_id),
            "hosts":       self.get_hosts(session_id),
            "ports":       self.get_ports(session_id),
            "findings":    self.get_findings(session_id),
            "stats":       self.stats(session_id),
        }
