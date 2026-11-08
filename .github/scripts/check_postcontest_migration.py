"""Exercise additive migration of an existing clone family without losing rows."""

from __future__ import annotations

import gc
import sqlite3
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ctf_agent.db import Settings, connect, initialize


def run() -> None:
    with TemporaryDirectory(ignore_cleanup_errors=True) as temporary:
        root = Path(temporary)
        settings = Settings(root / "data", root / "db", root / "config", root / "logs",
                            storage_min_free_bytes=0, auth_mode="nologin")
        initialize(settings)
        with connect(settings) as db:
            db.execute("INSERT INTO workspaces(id,name,created_at,updated_at) VALUES('w','old contest','t','t')")
            db.execute("INSERT INTO challenges(id,workspace_id,name,created_at,updated_at) VALUES('a','w','Original','t','t')")
            db.execute("INSERT INTO challenges(id,workspace_id,name,created_at,updated_at) VALUES('b','w','Original copy','t','t')")
            for member in ('a', 'b'):
                db.execute("INSERT INTO challenge_clone_members VALUES('w',?,'a','t')", (member,))
            # The pre-upgrade database did not have either challenge column.
            db.execute("ALTER TABLE challenges DROP COLUMN canonical_name")
            db.execute("ALTER TABLE challenges DROP COLUMN deleted_at")
            db.execute("ALTER TABLE users DROP COLUMN ultra_escalation_default")
            db.execute("ALTER TABLE users DROP COLUMN avatar_seed")
        initialize(settings)
        with connect(settings) as db:
            root_row = db.execute("SELECT name,deleted_at FROM challenges WHERE id='a'").fetchone()
            clone = db.execute("SELECT name,canonical_name,deleted_at FROM challenges WHERE id='b'").fetchone()
            assert tuple(root_row) == ('Original', None)
            assert tuple(clone) == ('Original copy', 'Original', None)
            assert db.execute("SELECT COUNT(*) FROM challenge_clone_members").fetchone()[0] == 2
            columns = {row[1] for row in db.execute('PRAGMA table_info(users)')}
            assert {'ultra_escalation_default', 'avatar_seed'} <= columns
            assert db.execute('PRAGMA quick_check').fetchone()[0] == 'ok'
        gc.collect()
    print('PASS: existing clone, user and workspace data survive migration')


if __name__ == '__main__':
    run()
