"""Regression checks for remote addresses embedded in CTFd challenge text."""

import sys
import sqlite3
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from ctf_agent.ctfd import ImportJobs, ctfd_remote_state


def run() -> None:
    site = "https://ctf.example.org"
    cases = [
        ("nc field.example.org 31337", "nc other.example.org 5555", "nc field.example.org 31337", "endpoint"),
        ("", "Connect with `nc challenge.example.org 31337`.", "nc challenge.example.org 31337", "endpoint"),
        ("", "Try [the service](http://challenge.example.org:8080/).", "http://challenge.example.org:8080/", "endpoint"),
        ("", "Target: challenge.example.org:31337", "challenge.example.org:31337", "endpoint"),
        ("", "See https://ctf.example.org/challenges for instructions.", "", "unknown"),
        ("", "Service: https://ctf.example.org:8443/", "https://ctf.example.org:8443/", "endpoint"),
        ("", "nc ctf.example.org 31337", "nc ctf.example.org 31337", "endpoint"),
        ("", "nc sandbox 1337", "nc sandbox 1337", "endpoint"),
        ("", "Broken address http://x.example.org:70000/", "", "unknown"),
        ("", "Download https://files.example.org/task.zip and inspect it.", "", "unknown"),
        ("", "Source: https://github.com/example/repo", "", "unknown"),
        ("", "Choose http://one.example.org/ or http://two.example.org/", "", "unknown"),
        ("", "There is no remote service; analyze the attachment.", "", "none"),
        ("", "원격 대상은 존재하지 않습니다. 첨부 파일을 분석하세요.", "", "none"),
    ]
    for explicit, description, expected, mode in cases:
        actual = ctfd_remote_state(explicit, description, site)
        assert actual == (expected, mode), (description, actual)
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.execute("CREATE TABLE challenges(id TEXT,workspace_id TEXT,name TEXT,category TEXT,"
               "description TEXT,remote TEXT,remote_mode TEXT,ctfd_id INTEGER,ctfd_url TEXT)")
    db.execute("CREATE TABLE ctfd_imported_fields(challenge_id TEXT,workspace_id TEXT,"
               "source_url TEXT,remote_id INTEGER,name TEXT,category TEXT,description TEXT,"
               "remote TEXT,remote_mode TEXT)")
    db.execute("INSERT INTO challenges VALUES(?,?,?,?,?,?,?,?,?)",
               ("challenge", "workspace", "Task", "web", "old", "nc old.example.org 31337",
                "endpoint", 7, site))
    db.execute("INSERT INTO ctfd_imported_fields VALUES(?,?,?,?,?,?,?,?,?)",
               ("challenge", "workspace", site, 7, "Task", "web", "old",
                "nc old.example.org 31337", "endpoint"))
    incoming = {"id": 7, "name": "Task", "category": "web",
                "description": "Connect with nc new.example.org 31337", "remote": ""}
    fields = ImportJobs.refresh_field_diff(db, "workspace", "challenge", site, incoming)
    endpoint = next(field for field in fields if field["field"] == "remote")
    assert endpoint["incoming"] == "nc new.example.org 31337" and endpoint["selectable"]
    db.close()
    print(f"PASS: {len(cases)} CTFd body remote cases")


if __name__ == "__main__":
    run()
