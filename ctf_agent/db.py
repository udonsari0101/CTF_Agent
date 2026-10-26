"""Storage settings and database setup. All timestamps are UTC ISO 8601."""

from __future__ import annotations

import os
import sqlite3
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    db_dir: Path
    config_dir: Path
    log_dir: Path
    public_origin: str = ""
    cookie_secure: bool = False
    session_hours: int = 12
    storage_min_free_bytes: int = 1024 * 1024 * 1024
    trust_cf_connecting_ip: bool = False
    auth_mode: str = "password"
    allow_web_bootstrap: bool = False

    def __post_init__(self) -> None:
        mode = str(self.auth_mode).strip().lower()
        if mode not in {"password", "nologin"}:
            raise ValueError("CTF_AUTH_MODE must be 'password' or 'nologin'.")
        object.__setattr__(self, "auth_mode", mode)

    @property
    def database_path(self) -> Path:
        return self.db_dir / "ctf_agent.sqlite3"

    @classmethod
    def from_env(cls) -> "Settings":
        data = Path(os.environ.get("CTF_DATA_DIR", "/data"))
        return cls(
            data_dir=data,
            db_dir=Path(os.environ.get("CTF_DB_DIR", "/database/sqlite")),
            config_dir=Path(os.environ.get("CTF_CONFIG_DIR", str(data / "config"))),
            log_dir=Path(os.environ.get("CTF_LOG_DIR", "/database/logs")),
            public_origin=os.environ.get("CTF_PUBLIC_ORIGIN", "").rstrip("/"),
            cookie_secure=os.environ.get("CTF_COOKIE_SECURE", "false").lower() == "true",
            storage_min_free_bytes=int(os.environ.get("CTF_STORAGE_MIN_FREE_BYTES", "1073741824")),
            trust_cf_connecting_ip=os.environ.get("CTF_TRUST_CF_CONNECTING_IP", "false").lower() == "true",
            auth_mode=os.environ.get("CTF_AUTH_MODE", "password"),
            allow_web_bootstrap=os.environ.get("CTF_ALLOW_WEB_BOOTSTRAP", "false").lower() == "true",
        )


SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin','user')), active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
    created_at TEXT NOT NULL, last_login_at TEXT
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY, csrf_token TEXT NOT NULL, expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS login_attempts (client TEXT NOT NULL, attempted_at INTEGER NOT NULL);
CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts(client, attempted_at);
CREATE TABLE IF NOT EXISTS workspaces (
    id TEXT PRIMARY KEY, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
    flag_format TEXT,
    open_challenge_after_create INTEGER NOT NULL DEFAULT 0 CHECK(open_challenge_after_create IN (0,1)),
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS challenges (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name TEXT NOT NULL, category TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'pending' CHECK(status IN ('pending','running','stopped','failed','flag_found','solved')),
    previous_status TEXT, completion_source TEXT CHECK(completion_source IN ('manual','agent') OR completion_source IS NULL),
    flag TEXT, notes TEXT NOT NULL DEFAULT '', remote TEXT NOT NULL DEFAULT '',
    remote_mode TEXT NOT NULL DEFAULT 'unknown' CHECK(remote_mode IN ('unknown','none','endpoint')),
    ctfd_id INTEGER, ctfd_url TEXT,
    created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_challenges_workspace ON challenges(workspace_id, status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_challenges_ctfd ON challenges(workspace_id, ctfd_url, ctfd_id)
    WHERE ctfd_id IS NOT NULL AND ctfd_url IS NOT NULL;
CREATE TABLE IF NOT EXISTS attachments (
    id TEXT PRIMARY KEY,
    workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    challenge_id TEXT NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    original_name TEXT NOT NULL, stored_name TEXT NOT NULL, size INTEGER NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_attachments_challenge ON attachments(workspace_id, challenge_id);
"""


def connect(settings: Settings) -> sqlite3.Connection:
    connection = sqlite3.connect(settings.database_path, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=15000")
    return connection


def initialize(settings: Settings) -> None:
    for directory in (settings.data_dir, settings.db_dir, settings.config_dir, settings.log_dir):
        directory.mkdir(parents=True, exist_ok=True)
    with connect(settings) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.executescript(SCHEMA)
        connection.execute("BEGIN IMMEDIATE")
        metadata = dict(connection.execute("SELECT key,value FROM meta").fetchall())
        owner_id = metadata.get("legacy_owner_id")
        if not owner_id:
            owner_id = uuid.uuid4().hex
            legacy_hash = metadata.get("admin_password_hash", "")
            username = metadata.get("admin_username") or ("admin" if legacy_hash else os.environ.get("CTF_BOOTSTRAP_USERNAME", "admin").strip())
            if not username or len(username) > 100 or any(ord(c) < 32 for c in username):
                raise RuntimeError("CTF bootstrap username is invalid.")
            connection.execute("INSERT INTO users VALUES(?,?,?,'admin',1,?,NULL)",
                               (owner_id, username, legacy_hash, datetime.now(timezone.utc).isoformat()))
            connection.execute("INSERT INTO meta(key,value) VALUES('legacy_owner_id',?)", (owner_id,))
            connection.execute("INSERT OR IGNORE INTO meta(key,value) VALUES('admin_username',?)", (username,))
        for table, column in (("sessions", "user_id"), ("workspaces", "owner_user_id")):
            columns = {row[1] for row in connection.execute(f"PRAGMA table_info({table})")}
            if column not in columns:
                connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} TEXT REFERENCES users(id)")
            connection.execute(f"UPDATE {table} SET {column}=? WHERE {column} IS NULL", (owner_id,))
        workspace_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(workspaces)")
        }
        if "open_challenge_after_create" not in workspace_columns:
            connection.execute(
                "ALTER TABLE workspaces ADD COLUMN "
                "open_challenge_after_create INTEGER NOT NULL DEFAULT 0"
            )
        challenge_columns = {
            row[1] for row in connection.execute("PRAGMA table_info(challenges)")
        }
        if "remote" not in challenge_columns:
            # A nullable-free default keeps this additive migration readable by
            # the previous generation-2 release during a deployment rollback.
            connection.execute(
                "ALTER TABLE challenges ADD COLUMN remote TEXT NOT NULL DEFAULT ''"
            )
        if "remote_mode" not in challenge_columns:
            # Empty legacy values were ambiguous, so retain that uncertainty.
            # A non-empty value is the only legacy state that proves an endpoint.
            connection.execute(
                "ALTER TABLE challenges ADD COLUMN remote_mode TEXT NOT NULL DEFAULT 'unknown'"
            )
            connection.execute(
                "UPDATE challenges SET remote_mode='endpoint' WHERE TRIM(remote)<>''"
            )
        # Before this marker was introduced, CTFd imports with an explicitly
        # empty connection_info were stored as ``unknown``.  That value is
        # correct for legacy/manual challenges but wrong for an authoritative
        # CTFd detail response.  Apply the data correction once so a user may
        # still deliberately edit an imported challenge back to ``unknown``
        # after the migration if its description references an external host.
        if metadata.get("ctfd_empty_remote_mode_migrated") != "1":
            connection.execute(
                """UPDATE challenges SET remote_mode='none'
                     WHERE remote_mode='unknown' AND TRIM(remote)=''
                       AND ctfd_id IS NOT NULL AND ctfd_url IS NOT NULL"""
            )
            connection.execute(
                """INSERT INTO meta(key,value)
                   VALUES('ctfd_empty_remote_mode_migrated','1')
                   ON CONFLICT(key) DO UPDATE SET value='1'"""
            )
        connection.execute("CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id)")
        connection.execute("CREATE INDEX IF NOT EXISTS idx_workspaces_owner ON workspaces(owner_user_id,updated_at)")
        # Generation 3 marks the multi-slot solver exchange. Once this marker
        # is committed, a generation-2 singleton release must not be started
        # against the migrated active/credential layout during rollback.
        connection.execute("INSERT INTO meta(key,value) VALUES('schema_version','3') ON CONFLICT(key) DO UPDATE SET value='3'")
