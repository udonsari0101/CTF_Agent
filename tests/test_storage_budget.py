import errno
import multiprocessing
import os
import sqlite3
import sys
import threading

import pytest

from ctf_agent.storage_budget import StorageBudget, StorageBudgetError


def coordinator(tmp_path, minimum=50):
    database = tmp_path / "budget.sqlite3"

    def connect():
        connection = sqlite3.connect(database, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    return StorageBudget(tmp_path / "data", connect, minimum_free_bytes=minimum), connect


def test_minimum_free_floor_defaults_to_one_gib_and_is_environment_configurable(tmp_path, monkeypatch):
    monkeypatch.delenv("CTF_STORAGE_MIN_FREE_BYTES", raising=False)
    _budget, connect = coordinator(tmp_path)
    defaulted = StorageBudget(tmp_path / "other-data", connect)
    assert defaulted.minimum_free_bytes == 1024 * 1024 * 1024
    monkeypatch.setenv("CTF_STORAGE_MIN_FREE_BYTES", "123456")
    configured = StorageBudget(tmp_path / "configured-data", connect)
    assert configured.minimum_free_bytes == 123456


def test_cross_instance_reservations_make_competing_allocations_atomic(tmp_path, monkeypatch):
    first, connect = coordinator(tmp_path)
    second = StorageBudget(first.data_dir, connect, minimum_free_bytes=50)
    monkeypatch.setattr(first, "_free", lambda: 150)
    monkeypatch.setattr(second, "_free", lambda: 150)
    gate = threading.Barrier(2)
    results = []

    def allocate(budget, key):
        gate.wait()
        try:
            budget.reserve(key, "upload", "owner", "workspace", "challenge", 100)
            results.append((key, "reserved"))
        except StorageBudgetError:
            results.append((key, "full"))

    threads = [
        threading.Thread(target=allocate, args=(first, "upload:first")),
        threading.Thread(target=allocate, args=(second, "upload:second")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(5)

    assert sorted(state for _, state in results) == ["full", "reserved"]
    rows = first.snapshot(kind="upload")
    assert len(rows) == 1 and rows[0]["remaining_bytes"] == 100


@pytest.mark.skipif(sys.platform != "linux", reason="Linux flock contract")
def test_linux_flock_serializes_separate_processes(tmp_path):
    first, connect = coordinator(tmp_path)
    second = StorageBudget(first.data_dir, connect, minimum_free_bytes=50)
    context = multiprocessing.get_context("fork")
    holding = context.Event()
    release = context.Event()
    entered = context.Event()

    def hold_lock():
        with first.exclusive():
            holding.set()
            release.wait(5)

    def enter_later():
        with second.exclusive():
            entered.set()

    owner = context.Process(target=hold_lock)
    contender = context.Process(target=enter_later)
    owner.start()
    assert holding.wait(5)
    contender.start()
    assert not entered.wait(.25)
    release.set()
    owner.join(5)
    contender.join(5)
    assert owner.exitcode == contender.exitcode == 0 and entered.is_set()


def test_enospc_never_consumes_reservation_and_reconcile_reclaims_orphans(tmp_path, monkeypatch):
    budget, _ = coordinator(tmp_path, minimum=0)
    monkeypatch.setattr(budget, "_free", lambda: 100)
    budget.reserve("upload:crash", "upload", "owner", "workspace", "challenge", 10)
    partial = budget.data_dir / "partial"

    def fail_mid_write():
        partial.write_bytes(b"tail")
        raise OSError(errno.ENOSPC, "fixture disk full")

    with pytest.raises(OSError) as failure:
        budget.commit_reserved_write("upload:crash", 4, fail_mid_write)
    assert failure.value.errno == errno.ENOSPC
    assert budget.snapshot(kind="upload")[0]["remaining_bytes"] == 10

    # Startup metadata reconciliation discards the orphan reservation. The
    # physical tail remains charged naturally by disk free space.
    budget.reconcile_kind("upload", {})
    assert budget.snapshot(kind="upload") == []


def test_durable_write_and_metadata_advance_with_one_reservation_commit(tmp_path, monkeypatch):
    budget, connect = coordinator(tmp_path, minimum=0)
    monkeypatch.setattr(budget, "_free", lambda: 100)
    with connect() as db:
        db.execute("CREATE TABLE progress(id TEXT PRIMARY KEY, offset INTEGER NOT NULL)")
        db.execute("INSERT INTO progress VALUES('item',0)")
    budget.reserve("upload:item", "upload", "owner", "workspace", "challenge", 10)
    destination = budget.data_dir / "durable"

    def write():
        with destination.open("ab") as output:
            output.write(b"abcd")
            output.flush()
            os.fsync(output.fileno())

    budget.commit_reserved_write(
        "upload:item", 4, write,
        db_update=lambda db: db.execute("UPDATE progress SET offset=4 WHERE id='item'"),
    )
    with connect() as db:
        assert db.execute("SELECT offset FROM progress").fetchone()[0] == 4
    assert budget.snapshot()[0]["remaining_bytes"] == 6
    budget.release("upload:item")
    assert budget.snapshot() == []
