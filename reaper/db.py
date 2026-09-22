import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Optional
from contextlib import contextmanager

DB_PATH = Path.home() / ".reaper" / "reaper.db"
ACTIVE_SESSION_FILE = Path.home() / ".reaper" / "active_session"

PROFILES = ("internal", "external", "cloud", "ad", "web", "recon")
PROFILE_COLORS = {
    "internal": "blue",
    "external": "green",
    "cloud": "cyan",
    "ad": "red",
    "web": "magenta",
    "recon": "yellow",
}


def _ensure_dirs():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)


class Database:
    def __init__(self, path: Path = DB_PATH):
        _ensure_dirs()
        self.path = path
        self._init_schema()

    @contextmanager
    def _conn(self):
        conn = sqlite3.connect(str(self.path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _init_schema(self):
        with self._conn() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sessions (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    name        TEXT    NOT NULL,
                    target      TEXT    NOT NULL,
                    profile     TEXT    NOT NULL DEFAULT 'recon',
                    notes       TEXT    NOT NULL DEFAULT '',
                    created_at  TEXT    NOT NULL,
                    updated_at  TEXT    NOT NULL
                );

                CREATE TABLE IF NOT EXISTS findings (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id  INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                    module      TEXT    NOT NULL,
                    severity    TEXT    NOT NULL,
                    title       TEXT    NOT NULL,
                    description TEXT    NOT NULL DEFAULT '',
                    evidence    TEXT    NOT NULL DEFAULT '',
                    target      TEXT    NOT NULL DEFAULT '',
                    created_at  TEXT    NOT NULL
                );

                CREATE TABLE IF NOT EXISTS module_runs (
                    id           INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id   INTEGER NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
                    module_name  TEXT    NOT NULL,
                    status       TEXT    NOT NULL DEFAULT 'running',
                    command      TEXT    NOT NULL DEFAULT '',
                    output       TEXT    NOT NULL DEFAULT '',
                    started_at   TEXT    NOT NULL,
                    completed_at TEXT
                );
            """)

    # ── sessions ──────────────────────────────────────────────────────────────

    def create_session(self, name: str, target: str, profile: str = "recon") -> int:
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO sessions (name, target, profile, created_at, updated_at) VALUES (?,?,?,?,?)",
                (name, target, profile, now, now),
            )
            return cur.lastrowid  # type: ignore[return-value]

    def get_session(self, session_id: int) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM sessions WHERE id=?", (session_id,)).fetchone()
            return dict(row) if row else None

    def list_sessions(self) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM sessions ORDER BY created_at DESC").fetchall()
            return [dict(r) for r in rows]

    def update_session(self, session_id: int, **kwargs):
        if not kwargs:
            return
        now = datetime.utcnow().isoformat()
        kwargs["updated_at"] = now
        sets = ", ".join(f"{k}=?" for k in kwargs)
        vals = list(kwargs.values()) + [session_id]
        with self._conn() as conn:
            conn.execute(f"UPDATE sessions SET {sets} WHERE id=?", vals)

    def update_session_profile(self, session_id: int, profile: str):
        self.update_session(session_id, profile=profile)

    def delete_session(self, session_id: int):
        with self._conn() as conn:
            conn.execute("DELETE FROM sessions WHERE id=?", (session_id,))

    # ── active session ────────────────────────────────────────────────────────

    def set_active_session(self, session_id: int):
        _ensure_dirs()
        ACTIVE_SESSION_FILE.write_text(str(session_id), encoding="utf-8")

    def get_active_session_id(self) -> Optional[int]:
        if ACTIVE_SESSION_FILE.exists():
            try:
                return int(ACTIVE_SESSION_FILE.read_text(encoding="utf-8").strip())
            except ValueError:
                pass
        return None

    def get_active_session(self) -> Optional[dict]:
        sid = self.get_active_session_id()
        return self.get_session(sid) if sid is not None else None

    def clear_active_session(self):
        if ACTIVE_SESSION_FILE.exists():
            ACTIVE_SESSION_FILE.unlink()

    # ── findings ──────────────────────────────────────────────────────────────

    def add_finding(
        self,
        session_id: int,
        module: str,
        severity: str,
        title: str,
        description: str = "",
        evidence: str = "",
        target: str = "",
    ) -> int:
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO findings "
                "(session_id, module, severity, title, description, evidence, target, created_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (session_id, module, severity, title, description, evidence, target, now),
            )
            return cur.lastrowid  # type: ignore[return-value]

    def get_findings(self, session_id: int, severity: Optional[str] = None) -> list[dict]:
        with self._conn() as conn:
            if severity:
                rows = conn.execute(
                    "SELECT * FROM findings WHERE session_id=? AND severity=? ORDER BY created_at DESC",
                    (session_id, severity),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM findings WHERE session_id=? ORDER BY created_at DESC",
                    (session_id,),
                ).fetchall()
            return [dict(r) for r in rows]

    def findings_count(self, session_id: int) -> dict:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT severity, COUNT(*) as cnt FROM findings WHERE session_id=? GROUP BY severity",
                (session_id,),
            ).fetchall()
            return {r["severity"]: r["cnt"] for r in rows}

    # ── module runs ───────────────────────────────────────────────────────────

    def start_module_run(self, session_id: int, module_name: str, command: str = "") -> int:
        now = datetime.utcnow().isoformat()
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO module_runs (session_id, module_name, status, command, started_at) "
                "VALUES (?,?,?,?,?)",
                (session_id, module_name, "running", command, now),
            )
            return cur.lastrowid  # type: ignore[return-value]

    def complete_module_run(self, run_id: int, output: str, success: bool, command: str = ""):
        now = datetime.utcnow().isoformat()
        status = "completed" if success else "failed"
        with self._conn() as conn:
            if command:
                conn.execute(
                    "UPDATE module_runs SET status=?, output=?, command=?, completed_at=? WHERE id=?",
                    (status, output[-50000:], command, now, run_id),  # cap output at 50k chars
                )
            else:
                conn.execute(
                    "UPDATE module_runs SET status=?, output=?, completed_at=? WHERE id=?",
                    (status, output[-50000:], now, run_id),
                )

    def get_module_runs(self, session_id: int) -> list[dict]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM module_runs WHERE session_id=? ORDER BY started_at DESC",
                (session_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_module_run(self, run_id: int) -> Optional[dict]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM module_runs WHERE id=?", (run_id,)).fetchone()
            return dict(row) if row else None
