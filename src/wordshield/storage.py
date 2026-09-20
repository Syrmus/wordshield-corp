from __future__ import annotations

import base64
import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

from .crypto import KeyProvider, decrypt, encrypt, new_key


class SessionStore:
    def __init__(self, data_dir: Path):
        self.root = data_dir
        self.blobs = data_dir / "blobs"
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.blobs.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.db = data_dir / "sessions.sqlite3"
        self.keys = KeyProvider(data_dir)
        with self._conn() as c:
            c.execute("""CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY, prefix TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL, state TEXT NOT NULL, wrapped_key BLOB NOT NULL,
                wrapped_raw_key BLOB, raw_blob TEXT, findings_blob TEXT, mapping_blob TEXT,
                entity_count INTEGER NOT NULL DEFAULT 0,
                qwen_blob TEXT, privacy_blob TEXT,
                completed_blocks INTEGER NOT NULL DEFAULT 0,
                total_blocks INTEGER NOT NULL DEFAULT 0,
                error_code TEXT
            )""")
            columns = {row[1] for row in c.execute("PRAGMA table_info(sessions)")}
            if "wrapped_raw_key" not in columns:
                c.execute("ALTER TABLE sessions ADD COLUMN wrapped_raw_key BLOB")
            for name, definition in (
                ("qwen_blob", "TEXT"),
                ("privacy_blob", "TEXT"),
                ("completed_blocks", "INTEGER NOT NULL DEFAULT 0"),
                ("total_blocks", "INTEGER NOT NULL DEFAULT 0"),
                ("error_code", "TEXT"),
                ("gliner_blob", "TEXT"),
                ("detector_blob", "TEXT"),
                ("stage", "TEXT NOT NULL DEFAULT 'detecting'"),
                ("completed_chunks", "INTEGER NOT NULL DEFAULT 0"),
                ("total_chunks", "INTEGER NOT NULL DEFAULT 0"),
                ("metadata_blob", "TEXT"),
                ("result_blob", "TEXT"),
                ("original_blob", "TEXT"),
            ):
                if name not in columns:
                    c.execute(f"ALTER TABLE sessions ADD COLUMN {name} {definition}")
            c.execute('CREATE TABLE IF NOT EXISTS session_numbers (number INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT UNIQUE NOT NULL)')
            for row in c.execute('SELECT id FROM sessions ORDER BY created_at, id').fetchall():
                if not c.execute('SELECT 1 FROM session_numbers WHERE session_id=?',(row[0],)).fetchone():
                    c.execute('INSERT INTO session_numbers(session_id) VALUES (?)',(row[0],))

    def _conn(self):
        c = sqlite3.connect(self.db)
        c.row_factory = sqlite3.Row
        c.execute("PRAGMA secure_delete=ON")
        return c

    def create(self, raw: bytes, retention_days: int) -> tuple[str, str]:
        sid = uuid4().hex
        with self._conn() as c:
            used = {r[0] for r in c.execute("SELECT prefix FROM sessions")}
        prefix = "GLOB"
        while prefix == "GLOB" or prefix in used:
            prefix = base64.b32encode(new_key()[:3]).decode().rstrip("=")[:4]
        key = new_key()
        raw_key = new_key()
        master = self.keys.master_key()
        wrapped = encrypt(master, key, f"key:{sid}".encode())
        wrapped_raw = encrypt(master, raw_key, f"raw-key:{sid}".encode())
        raw_name = f"{sid}.raw.enc"
        (self.blobs / raw_name).write_bytes(
            encrypt(raw_key, raw, f"raw:{sid}".encode())
        )
        now = datetime.now(UTC)
        with self._conn() as c:
            c.execute(
                "INSERT INTO sessions (id,prefix,created_at,expires_at,state,wrapped_key,wrapped_raw_key,raw_blob,findings_blob,mapping_blob,entity_count) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (
                    sid,
                    prefix,
                    now.isoformat(),
                    (now + timedelta(days=retention_days)).isoformat(),
                    "created",
                    wrapped,
                    wrapped_raw,
                    raw_name,
                    None,
                    None,
                    0,
                ),
            )
            c.execute('INSERT INTO session_numbers(session_id) VALUES (?)',(sid,))
        return sid, prefix

    def _row(self, sid: str):
        with self._conn() as c:
            row = c.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
        if not row:
            raise KeyError(sid)
        if datetime.fromisoformat(row["expires_at"]) <= datetime.now(UTC):
            self.delete(sid)
            raise KeyError(sid)
        return row

    def _session_key(self, row) -> bytes:
        return decrypt(
            self.keys.master_key(), row["wrapped_key"], f"key:{row['id']}".encode()
        )

    def raw(self, sid: str) -> bytes:
        row = self._row(sid)
        if not row["raw_blob"] or not row["wrapped_raw_key"]:
            raise KeyError("original already destroyed")
        raw_key = decrypt(
            self.keys.master_key(), row["wrapped_raw_key"], f"raw-key:{sid}".encode()
        )
        return decrypt(
            raw_key, (self.blobs / row["raw_blob"]).read_bytes(), f"raw:{sid}".encode()
        )

    def put_json(self, sid: str, field: str, payload: object) -> None:
        if field not in {"findings_blob", "mapping_blob", "qwen_blob", "privacy_blob", "gliner_blob", "detector_blob", "metadata_blob"}:
            raise ValueError(field)
        row = self._row(sid)
        name = f"{sid}.{field}.enc"
        data = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode()
        temporary = self.blobs / (name + "." + uuid4().hex + ".tmp")
        temporary.write_bytes(
            encrypt(self._session_key(row), data, f"{field}:{sid}".encode())
        )
        temporary.replace(self.blobs / name)
        with self._conn() as c:
            c.execute(f"UPDATE sessions SET {field}=? WHERE id=?", (name, sid))

    def get_json(self, sid: str, field: str):
        row = self._row(sid)
        name = row[field]
        if not name:
            return None
        data = decrypt(
            self._session_key(row),
            (self.blobs / name).read_bytes(),
            f"{field}:{sid}".encode(),
        )
        return json.loads(data)

    def put_result(self, sid: str, raw: bytes) -> None:
        row = self._row(sid)
        name = f"{sid}.result.enc"
        temporary = self.blobs / (name + "." + uuid4().hex + ".tmp")
        temporary.write_bytes(encrypt(self._session_key(row), raw, f"result:{sid}".encode()))
        temporary.replace(self.blobs / name)
        with self._conn() as c:
            c.execute("UPDATE sessions SET result_blob=? WHERE id=?", (name, sid))

    def put_original(self, sid: str, raw: bytes) -> None:
        """Keep the exact uploaded DOC separately from its working DOCX conversion."""
        row = self._row(sid)
        name = f"{sid}.original.enc"
        temporary = self.blobs / (name + "." + uuid4().hex + ".tmp")
        temporary.write_bytes(encrypt(self._session_key(row), raw, f"original:{sid}".encode()))
        temporary.replace(self.blobs / name)
        with self._conn() as c:
            c.execute("UPDATE sessions SET original_blob=? WHERE id=?", (name, sid))

    def original(self, sid: str) -> bytes:
        row = self._row(sid)
        if row["original_blob"]:
            return decrypt(self._session_key(row), (self.blobs / row["original_blob"]).read_bytes(),
                           f"original:{sid}".encode())
        metadata = self.get_json(sid, "metadata_blob") or {}
        if (metadata.get("filename") or "").lower().endswith(".doc"):
            raise KeyError("legacy DOC original was not retained")
        return self.raw(sid)

    def result(self, sid: str) -> bytes:
        row = self._row(sid)
        if not row["result_blob"] or row["state"] != "exported":
            raise KeyError("result unavailable")
        return decrypt(self._session_key(row), (self.blobs / row["result_blob"]).read_bytes(),
                       f"result:{sid}".encode())

    def update_state(
        self, sid: str, state: str, entity_count: int | None = None
    ) -> None:
        with self._conn() as c:
            if entity_count is None:
                c.execute(
                    "UPDATE sessions SET state=?, error_code=NULL WHERE id=?",
                    (state, sid),
                )
            else:
                c.execute(
                    "UPDATE sessions SET state=?, entity_count=?, error_code=NULL WHERE id=?",
                    (state, entity_count, sid),
                )

    def update_error(self, sid: str, code: str) -> None:
        with self._conn() as c:
            c.execute("UPDATE sessions SET state='failed', error_code=? WHERE id=?", (code, sid))

    def update_progress(self, sid: str, completed: int, total: int) -> None:
        with self._conn() as c:
            c.execute(
                "UPDATE sessions SET completed_blocks=?, total_blocks=? WHERE id=?",
                (completed, total, sid),
            )

    def update_stage(self, sid: str, stage: str, completed: int, total: int) -> None:
        with self._conn() as c:
            c.execute("UPDATE sessions SET stage=?, completed_chunks=?, total_chunks=? WHERE id=?",
                      (stage, completed, total, sid))

    def destroy_raw(self, sid: str) -> None:
        row = self._row(sid)
        if row["raw_blob"]:
            (self.blobs / row["raw_blob"]).unlink(missing_ok=True)
        with self._conn() as c:
            c.execute(
                "UPDATE sessions SET raw_blob=NULL, wrapped_raw_key=NULL WHERE id=?",
                (sid,),
            )

    def find_by_prefix(self, prefix: str):
        with self._conn() as c:
            row = c.execute(
                "SELECT * FROM sessions WHERE prefix=?", (prefix,)
            ).fetchone()
        if not row:
            raise KeyError(prefix)
        return self._row(row["id"])

    def list(self) -> list[dict]:
        self.purge()
        with self._conn() as c:
            return [
                dict(r)
                for r in c.execute(
                    "SELECT id,prefix,created_at,expires_at,state,entity_count,result_blob IS NOT NULL AS has_result,raw_blob IS NOT NULL AS has_raw,original_blob IS NOT NULL AS has_original FROM sessions ORDER BY created_at DESC"
                )
            ]

    def delete(self, sid: str) -> None:
        with self._conn() as c:
            row = c.execute("SELECT * FROM sessions WHERE id=?", (sid,)).fetchone()
            if row:
                for field in ("raw_blob", "findings_blob", "mapping_blob", "qwen_blob", "privacy_blob", "gliner_blob", "detector_blob", "metadata_blob", "result_blob", "original_blob"):
                    if row[field]:
                        (self.blobs / row[field]).unlink(missing_ok=True)
                c.execute("DELETE FROM sessions WHERE id=?", (sid,))

    def purge(self, upload_ttl_hours: int = 24) -> None:
        now = datetime.now(UTC)
        with self._conn() as c:
            rows = c.execute("SELECT * FROM sessions").fetchall()
        for row in rows:
            expired = datetime.fromisoformat(row["expires_at"]) <= now
            # A session exists only after a complete, validated upload. Failed or
            # interrupted analysis must not shorten the shared 90-day lifetime.
            if expired:
                self.delete(row["id"])
