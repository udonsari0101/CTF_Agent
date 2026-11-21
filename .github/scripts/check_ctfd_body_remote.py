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
        ("", "Host: chal.example.org\nPort: 31337", "chal.example.org:31337", "endpoint"),
        ("", "See https://ctf.example.org/challenges for instructions.", "", "unknown"),
        ("", "Service: https://ctf.example.org:8443/", "https://ctf.example.org:8443/", "endpoint"),
        ("", "Service: https://ctf.example.org/proxy/one", "https://ctf.example.org/proxy/one", "endpoint"),
        ("", "Service: <a href=\"https://ctf.example.org/proxy/two\">Open the instance</a>", "https://ctf.example.org/proxy/two", "endpoint"),
        ("", "<a href=\"https://ctf.example.org/proxy/three\">Open service</a>", "https://ctf.example.org/proxy/three", "endpoint"),
        ("", "<a href='https://ctf.example.org/proxy/four'>Launch</a>", "https://ctf.example.org/proxy/four", "endpoint"),
        ("", "<a href='https://ctf.example.org/proxy/five'>Start challenge</a>", "https://ctf.example.org/proxy/five", "endpoint"),
        ("", "[Launch](https://ctf.example.org/proxy/six)", "https://ctf.example.org/proxy/six", "endpoint"),
        ("", "https://challenge.example.org/", "https://challenge.example.org/", "endpoint"),
        ("", "Visit https://challenge.example.org/ to play.", "https://challenge.example.org/", "endpoint"),
        ("", "nc ctf.example.org 31337", "nc ctf.example.org 31337", "endpoint"),
        ("", "nc sandbox 1337", "nc sandbox 1337", "endpoint"),
        ("", "Broken address http://x.example.org:70000/", "", "unknown"),
        ("", "Download https://files.example.org/task.zip and inspect it.", "", "unknown"),
        ("", "Source: https://github.com/example/repo", "", "unknown"),
        ("", "Source: https://gitlab.com/team/chal", "", "unknown"),
        ("", "Source code at https://gitlab.com/team/chal", "", "unknown"),
        ("", "[Repository](https://gitlab.com/team/chal)", "", "unknown"),
        ("", "Source code: [repository](https://gitlab.com/team/chal)", "", "unknown"),
        ("", "[Source code](https://codeberg.org/team/chal)", "", "unknown"),
        ("", "The source is at https://example.org/intro then Service: https://ctf.example.org/proxy/chal", "https://ctf.example.org/proxy/chal", "endpoint"),
        ("", "Open the attachment: https://ctf.example.org/files/secret/chal", "", "unknown"),
        ("", "See http://ctf.example.org/challenges for tasks", "", "unknown"),
        ("", "Maybe try a tool like https://dogbolt.org/; it shows decompiler output.", "", "unknown"),
        ("", "Read the documentation at https://docs.example.org/ before analyzing the file.", "", "unknown"),
        ("", "Read https://example.org/guide before analyzing the file.", "", "unknown"),
        ("", "This challenge asks you to read https://example.org/guide before analyzing the binary.", "", "unknown"),
        ("", "문제 분석을 위해 https://docs.example.org/intro 문서를 읽으세요.", "", "unknown"),
        ("", "Read <a href=\"https://example.org/guide\">the guide</a> first.", "", "unknown"),
        ("", "<a href=\"https://example.org/landing\">Documentation</a>", "", "unknown"),
        ("", "<a target=\"_blank\" href=\"https://docs.example.org/intro\"><span>Docs</span></a>", "", "unknown"),
        ("", "The reference is at https://docs.example.org/intro and the service is https://challenge.example.org/", "https://challenge.example.org/", "endpoint"),
        ("", "See https://ctf.example.org/api/v1/challenges for details.", "", "unknown"),
        ("", "Try a tool like https://helper.example.org/ then connect to https://challenge.example.org/", "https://challenge.example.org/", "endpoint"),
        ("", "Choose http://one.example.org/ or http://two.example.org/", "", "unknown"),
        ("", "There is no remote service; analyze the attachment.", "", "none"),
        ("", "This challenge has no service. Read https://example.org/landing", "", "none"),
        ("", "No remote service: https://example.org/landing", "", "none"),
        ("", "No remote service; visit https://challenge.example.org/ to play instead.", "https://challenge.example.org/", "endpoint"),
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
