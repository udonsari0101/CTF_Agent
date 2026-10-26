import hashlib
import os
import stat
from pathlib import Path

import pytest

from ctf_agent.agent_workspace import (
    CATEGORIES,
    INITIAL_GOAL,
    NUDGE,
    POISON_REGOAL,
    SCAFFOLDS,
    assemble_manual,
    normalize_categories,
    prepare_agent_workspace,
)


# These digests pin the distributed playbooks and scaffolds. Changes to their
# content must be reviewed explicitly so the solver method is not simplified.
ORIGINAL_ASSETS = {
    "prompts/base.md": (7582, "0fed64c34fa17ebf08a531bee626ec270b4011db54abdef8280dc05c297c671a"),
    "prompts/remote_only.md": (5791, "a90ff16ed2388c2931d6813f2cad2148f92106d8b629b7e795909eb21089c3bb"),
    "prompts/skill_ai-ml.md": (10209, "e56055b0fb5d81946383c79fb359b952fdceba98a3f469d59c9b3dae2b7bf652"),
    "prompts/skill_blockchain.md": (11938, "88a789b42c4f63ba60cdf4a19d9a9b595b89e765e48c01d08dbeee33540273dc"),
    "prompts/skill_crypto.md": (13889, "35f4b733e0adb7f633e64c6e559c4a573788fdfd6a91c89626e6d9dcaea17fd9"),
    "prompts/skill_forensics.md": (18493, "4eaceb69359ff360437c3665f6ef9c67eaccc40a3d61627b022ade3b9e2fac6b"),
    "prompts/skill_misc.md": (21698, "b90f56c0566efda27ad17759c5b44209334116d30989afc927cd0481361622eb"),
    "prompts/skill_osint.md": (12324, "88a5a1fdd83dd50dd0f93609a47ed8a11b9a8ff2325167ac34f3aa72a9949b6a"),
    "prompts/skill_pwn.md": (20233, "858f49cd14076a7c7a1cf096dfe96862682f26e777f9de85e6f12458d22607a3"),
    "prompts/skill_rev.md": (12276, "7faa125db9a3581d4faa5aab286f5f0ea8be8510c0b937d0717e80a535c26f66"),
    "prompts/skill_unknown.md": (7494, "777dd66795e2ef3747675d22e0b5bd03738986626fb7e194a3b22fa3d2377a50"),
    "prompts/skill_web.md": (25636, "9a5d25486174fcb15a604869df687925a0aaa3a1e14a8d90c27638a6ca9f07da"),
    "prompts/web_template.md": (1427, "f597d4b1e632c34fd692870e4cd77ec2a9b5415dca9fb157a8f4884d4335360b"),
    "scaffolds/ANALYSIS.md": (1039, "9da1e2a76b40722f460d438f5ad01cdf880b6c8138c28a2fce679af8729303bb"),
    "scaffolds/NEXT.md": (1362, "0d58fa2dd5baabb643cea7e15b093db9640223eaf45aecda1a13f54656588d58"),
    "scaffolds/VULN.md": (1446, "e63302baed1dfd5853f0239e1a1e6f8595195273fde9fc14cefc07ccb6749768"),
}


def _assets_root() -> Path:
    import ctf_agent

    return Path(ctf_agent.__file__).parent / "agent_assets"


def test_original_prompt_skill_and_scaffold_assets_are_byte_exact():
    root = _assets_root()
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*.md")
        if path.is_file()
    }
    assert actual == set(ORIGINAL_ASSETS)
    assert sum(size for name, (size, _) in ORIGINAL_ASSETS.items() if name.startswith("prompts/")) == 168_990
    assert sum(size for name, (size, _) in ORIGINAL_ASSETS.items() if name.startswith("scaffolds/")) == 3_847
    for name, (expected_size, expected_digest) in ORIGINAL_ASSETS.items():
        payload = (root / name).read_bytes()
        assert len(payload) == expected_size, name
        assert hashlib.sha256(payload).hexdigest() == expected_digest, name


def test_category_selection_uses_original_canonical_order_and_safe_fallback():
    assert CATEGORIES == (
        "web",
        "pwn",
        "rev",
        "crypto",
        "misc",
        "forensics",
        "blockchain",
        "ai-ml",
        "osint",
        "unknown",
    )
    assert normalize_categories("PWN, web / pwn") == ("web", "pwn")
    assert normalize_categories("ai-ml + forensics") == ("forensics", "ai-ml")
    assert normalize_categories("Reversing & Cryptography") == ("rev", "crypto")
    assert normalize_categories("Pwnable, Forensic") == ("pwn", "forensics")
    assert normalize_categories("Binary Exploitation / PPC") == ("pwn", "misc")
    assert normalize_categories("web / unknown") == ("web",)
    assert normalize_categories("mobile") == ("unknown",)
    assert normalize_categories("") == ("unknown",)


def test_manual_keeps_original_base_and_only_appends_worker_handoff():
    base = (_assets_root() / "prompts" / "base.md").read_text(encoding="utf-8")
    manual = assemble_manual(
        ("web", "crypto"),
        challenge_name="Cookie Forge",
        remote="https://challenge.example",
        remote_access=True,
    )
    base_start = manual.index(base.strip())
    assert base_start > 0
    assert manual[base_start + len(base.strip()) :].startswith("\n\n---\n")
    assert "`../../skills/web.md`, `../../skills/crypto.md`" in manual
    assert "`../chal_desc.md`" in manual
    assert 'submit-flag "<flag>"' in manual
    assert "direct Internet sockets and DNS are available" in manual
    assert "`curl`, `nc`, pwntools" in manual
    assert "ctf-connect" not in manual
    assert "separate turn writes the final Notion-ready write-up" in manual
    assert "Treat category" in manual and "if evidence conflicts" in manual
    assert "job-local tmux socket" in manual


def test_nonstandard_category_triggers_evidence_based_field_triage():
    manual = assemble_manual(
        normalize_categories("welcome"),
        challenge_name="Sanity",
        remote_mode="none",
    )

    assert "Category metadata: `unknown`" in manual
    assert "blank or nonstandard" in manual
    assert "identify the most likely field during analysis" in manual
    assert "`../../skills/unknown.md`" in manual


def test_original_driver_loop_messages_are_byte_exact():
    expected = {
        "INITIAL_GOAL": (879, "28878a3bdee60611ae6714107a3307b883230e507c2bbd1c1850da8beeccbc08"),
        "NUDGE": (532, "0f0263bfc585cb5c683fc108edb7fc4acefbc7d6ceaaddacf43f2a4f87044d80"),
        "POISON_REGOAL": (446, "3b4942955f895de68aa921bcc727307027224eb3bb7350e5f577705f95064ae2"),
    }
    for name, value in {
        "INITIAL_GOAL": INITIAL_GOAL,
        "NUDGE": NUDGE,
        "POISON_REGOAL": POISON_REGOAL,
    }.items():
        payload = value.encode("utf-8")
        assert len(payload) == expected[name][0]
        assert hashlib.sha256(payload).hexdigest() == expected[name][1]


def test_remote_only_module_keeps_original_inline_semantics():
    module = (_assets_root() / "prompts" / "remote_only.md").read_text(encoding="utf-8").strip()
    remote_manual = assemble_manual(
        ("unknown",),
        challenge_name="Remote only",
        remote="tcp://challenge.example:31337",
        remote_only=True,
        remote_access=True,
    )
    assert module in remote_manual
    assert "make one bounded banner or protocol probe" in remote_manual
    no_server_manual = assemble_manual(
        ("unknown",),
        challenge_name="Static description",
        remote_only=True,
        no_server=True,
    )
    assert module not in no_server_manual
    assert "make one bounded banner or protocol probe" not in no_server_manual


def test_prepare_workspace_recreates_original_solver_topology(tmp_path):
    source = tmp_path / "staged-source"
    attachments = source / "attachments"
    attachments.mkdir(parents=True)
    (attachments / "0001_challenge.bin").write_bytes(b"\x7fELF\x00sample")
    (source / "README.txt").write_text("source material\n", encoding="utf-8")

    prepared = prepare_agent_workspace(
        tmp_path / "job",
        source,
        challenge_name="Stack School",
        challenge_text="Recover the flag from the supplied binary.",
        category="pwn",
        flag_format="SARI{...}",
        remote="tcp://challenge.example:31337",
        remote_access=True,
    )

    competition = tmp_path / "job" / "competition"
    challenge = competition / "challenge"
    assert prepared.workdir == challenge / "codex-workdir"
    assert prepared.brief == challenge / "chal_desc.md"
    assert prepared.skills == competition / "skills"
    assert (prepared.workdir / "attachments" / "0001_challenge.bin").read_bytes() == b"\x7fELF\x00sample"
    assert (prepared.workdir / "README.txt").read_text(encoding="utf-8") == "source material\n"
    assert (prepared.workdir / "tmp").is_dir()
    assert (prepared.workdir / "CLAUDE.md").read_bytes() == (
        prepared.workdir / "AGENTS.md"
    ).read_bytes()
    manual = (prepared.workdir / "AGENTS.md").read_text(encoding="utf-8")
    assert "worker records that command as the authoritative result handoff" in manual
    assert "required structured response" not in manual

    expected_skills = {f"{category}.md" for category in CATEGORIES} | {"remote_only.md"}
    assert {path.name for path in prepared.skills.iterdir()} == expected_skills
    for category in CATEGORIES:
        original = (_assets_root() / "prompts" / f"skill_{category}.md").read_text(encoding="utf-8")
        assert (prepared.skills / f"{category}.md").read_text(encoding="utf-8") == original.rstrip("\n") + "\n"
    remote = (_assets_root() / "prompts" / "remote_only.md").read_text(encoding="utf-8")
    assert (prepared.skills / "remote_only.md").read_text(encoding="utf-8") == remote.rstrip("\n") + "\n"

    brief = prepared.brief.read_text(encoding="utf-8")
    assert "# Stack School" in brief
    assert "Category: pwn" in brief
    assert "Flag format: SARI{...}" in brief
    assert "Remote: tcp://challenge.example:31337" in brief
    assert "Recover the flag from the supplied binary." in brief

    assert tuple(sorted(path.name for path in (prepared.workdir / "notes").iterdir())) == tuple(sorted(SCAFFOLDS))
    for name in SCAFFOLDS:
        original = (_assets_root() / "scaffolds" / name).read_text(encoding="utf-8")
        assert (prepared.workdir / "notes" / name).read_text(encoding="utf-8") == (
            original.replace("{{CHAL}}", "Stack School").rstrip("\n") + "\n"
        )

    if os.name != "nt":
        for path in [
            prepared.brief,
            prepared.workdir / "AGENTS.md",
            prepared.workdir / "CLAUDE.md",
            *prepared.skills.iterdir(),
        ]:
            assert stat.S_IMODE(path.stat().st_mode) == 0o400
        assert stat.S_IMODE((prepared.workdir / "README.txt").stat().st_mode) == 0o600


def test_prepare_workspace_rejects_linked_or_multiply_linked_source(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    original = source / "original.bin"
    original.write_bytes(b"payload")
    try:
        os.link(original, source / "alias.bin")
    except OSError:
        pytest.skip("hard links are unavailable on this filesystem")

    with pytest.raises(ValueError, match="unsupported file"):
        prepare_agent_workspace(
            tmp_path / "job",
            source,
            challenge_name="Linked input",
            challenge_text="Inspect the attachment.",
        )


def test_prepare_workspace_reserves_solver_path_for_a_validated_retry_snapshot(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "solver.py").write_text("print('untrusted collision')\n", encoding="utf-8")

    with pytest.raises(ValueError, match="reserved workspace path"):
        prepare_agent_workspace(
            tmp_path / "job",
            source,
            challenge_name="Solver collision",
            challenge_text="Inspect the attachment.",
        )


@pytest.mark.skipif(os.name == "nt", reason="Windows CI account cannot create symbolic links")
def test_readonly_source_view_keeps_multi_gib_input_out_of_bounded_scratch(tmp_path):
    source = tmp_path / "exchange" / "active" / "challenge"
    attachment = source / "attachments" / "huge.bin"
    attachment.parent.mkdir(parents=True)
    with attachment.open("wb") as stream:
        stream.seek(2 * 1024 * 1024 * 1024)
        stream.write(b"Z")

    prepared = prepare_agent_workspace(
        tmp_path / "job",
        source,
        readonly_source_view=source,
        challenge_name="Large binary",
        challenge_text="Inspect the multi-gibibyte sparse fixture.",
    )

    linked = prepared.workdir / "attachments" / "huge.bin"
    assert linked.is_symlink()
    assert linked.stat().st_size == 2 * 1024 * 1024 * 1024 + 1
    with linked.open("rb") as stream:
        stream.seek(-1, os.SEEK_END)
        assert stream.read() == b"Z"
    scratch_regular_bytes = sum(
        path.lstat().st_size
        for path in (tmp_path / "job").rglob("*")
        if path.is_file() and not path.is_symlink()
    )
    assert scratch_regular_bytes < 1024 * 1024


def test_readonly_source_view_rejects_a_different_inode_tree(tmp_path):
    source = tmp_path / "source"
    visible = tmp_path / "visible"
    source.mkdir()
    visible.mkdir()
    (source / "payload.bin").write_bytes(b"original")
    (visible / "payload.bin").write_bytes(b"substituted")

    with pytest.raises(ValueError, match="does not match"):
        prepare_agent_workspace(
            tmp_path / "job",
            source,
            readonly_source_view=visible,
            challenge_name="Mismatched view",
            challenge_text="Inspect the attachment.",
        )
