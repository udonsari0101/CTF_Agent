"""Build the per-job workspace used by the original ctf_agent solve loop.

The prompt and category playbooks in :mod:`ctf_agent.agent_assets` are copied
from the source archive.  This module only adapts their paths to the isolated
worker and appends the structured-result handoff used by the web service.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
from dataclasses import dataclass
from importlib.resources import files
from pathlib import Path

from .archive_workspace import (
    ArchiveInput,
    ArchivePolicy,
    ArchiveReport,
    extract_attachment_archives,
)


CATEGORIES = (
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
# CTFd category names are organizer-defined. Map only unambiguous, common
# variants; an unfamiliar label still goes through the original unknown triage.
CATEGORY_ALIASES = {
    "web": ("webapp", "web application"),
    "pwn": ("pwnable", "binary exploitation"),
    "rev": ("reversing", "reverse engineering", "reverse"),
    "crypto": ("cryptography", "cryptanalysis"),
    "misc": ("miscellaneous", "ppc", "programming puzzle"),
    "forensics": ("forensic", "digital forensics"),
    "ai-ml": ("ai/ml", "machine learning"),
}
SCAFFOLDS = ("ANALYSIS.md", "VULN.md", "NEXT.md")
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_RESERVED_TOP_LEVEL = {
    ".flag-candidate",
    ".remote-request",
    "AGENTS.md",
    "CLAUDE.md",
    "extracted",
    "notes",
    "solver.py",
    "tmp",
}


# Copied verbatim from the original driver. The web worker uses the same solve
# loop rather than replacing it with a generic one-shot prompt.
INITIAL_GOAL = (
    "You are competing to solve this CTF challenge; your job is to build a working "
    "exploit and capture the flag. Read your operating manual (CLAUDE.md or "
    "AGENTS.md here) and the read-only brief ../chal_desc.md, then work fully "
    "autonomously through the solve loop: recon -> open the relevant "
    "../../skills/<cat>.md -> analyze (decompose hard targets file/function-by-"
    "function) -> identify the vuln -> verify it's real and reaches the flag -> "
    "build solver.py -> on failure, branch (more skills only if relevant, check "
    "patch/CVE for 0/1-day, side-channels, re-chain the primitives you already have). "
    "Write notes/{ANALYSIS,VULN,NEXT}.md at each cycle end (don't read them at the "
    "start), keep scratch in tmp/. The REAL flag is on the remote (local flags are "
    "fake); solve any PoW. Submit with submit-flag \"<flag>\". Don't stop until it's "
    "accepted; don't grind — when stuck, vary the tactic."
)

NUDGE = (
    "Status check. Do NOT blind-repeat a failing approach. If you're stuck: write 3 "
    "falsifiable hypotheses in notes/NEXT.md for WHY it's failing and test each with "
    "a specific experiment (ask the debugger a precise question, not 'why doesn't "
    "this work?'). Re-scan the primitives you already hold for one you overlooked and "
    "try re-chaining them a different way. Then VARY the tactic — name the dead end "
    "in notes/NEXT.md and switch vuln class / tool / primitive (grep -> script, "
    "reason -> run/fuzz, local -> remote). Otherwise keep going."
)

POISON_REGOAL = (
    "The flag you submitted was WRONG. Record that exact string as POISON in "
    "notes/NEXT.md and never resubmit it. Re-analyze from notes/VULN.md and "
    "../chal_desc.md to find the REAL flag (check assumptions: encoding, offset, "
    "wrong primitive, wrong endpoint; and if you tested locally, a local/placeholder "
    "flag is NOT real — run solver.py against the remote and confirm the flag is in "
    "that run's output), then submit the correct flag with submit-flag."
)


@dataclass(frozen=True, slots=True)
class PreparedAgentWorkspace:
    workdir: Path
    brief: Path
    skills: Path
    archive_report: ArchiveReport = ArchiveReport()


def normalize_categories(value: str) -> tuple[str, ...]:
    lowered = value.lower() if isinstance(value, str) else ""
    selected = tuple(
        category for category in CATEGORIES if category != "unknown" and any(
            re.search(rf"(?<![a-z0-9]){re.escape(label)}(?![a-z0-9])", lowered)
            for label in (category, *CATEGORY_ALIASES.get(category, ()))
        )
    )
    return selected or ("unknown",)


def _asset_text(group: str, name: str) -> str:
    return files("ctf_agent").joinpath("agent_assets", group, name).read_text(encoding="utf-8")


def _write_readonly(path: Path, text: str) -> None:
    path.write_text(text.rstrip("\n") + "\n", encoding="utf-8")
    path.chmod(0o400)


def _copy_regular_tree(
    source: Path,
    destination: Path,
    *,
    readonly_source_view: Path | None = None,
) -> tuple[ArchiveInput, ...]:
    """Stage a coordinator-validated tree without following links.

    Production exposes the same exchange directory through a second,
    read-only bind mount.  In that mode each input is represented by a trusted
    absolute symlink instead of being copied into the job's disk scratch.
    The inode comparison prevents a mismatched or replaced view from being
    used.  Unit tests and non-container callers retain the copy behaviour.
    """

    source = Path(source)
    readonly_source_view = (
        Path(readonly_source_view) if readonly_source_view is not None else None
    )
    if readonly_source_view is not None:
        if (
            source.is_symlink()
            or readonly_source_view.is_symlink()
            or not source.is_dir()
            or not readonly_source_view.is_dir()
        ):
            raise ValueError("challenge source view is not a regular directory")
        try:
            if not os.path.samefile(source, readonly_source_view):
                raise ValueError("challenge source view does not match the staged input")
        except OSError as exc:
            raise ValueError("challenge source view cannot be verified") from exc

    staged_inputs: list[ArchiveInput] = []
    for current, directories, filenames in os.walk(source, followlinks=False):
        current_path = Path(current)
        relative = current_path.relative_to(source)
        target_dir = destination / relative
        target_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        for directory in directories:
            if relative == Path(".") and directory in _RESERVED_TOP_LEVEL:
                raise ValueError("challenge source collides with a reserved workspace path")
            details = (current_path / directory).lstat()
            if stat.S_ISLNK(details.st_mode) or not stat.S_ISDIR(details.st_mode):
                raise ValueError("challenge source contains an unsupported directory")
        for filename in filenames:
            if relative == Path(".") and filename in _RESERVED_TOP_LEVEL:
                raise ValueError("challenge source collides with a reserved workspace path")
            item = current_path / filename
            details = item.lstat()
            if stat.S_ISLNK(details.st_mode) or not stat.S_ISREG(details.st_mode) or details.st_nlink != 1:
                raise ValueError("challenge source contains an unsupported file")
            target = target_dir / filename
            if readonly_source_view is not None:
                visible = readonly_source_view / relative / filename
                try:
                    visible_details = visible.lstat()
                    same_file = os.path.samefile(item, visible)
                except OSError as exc:
                    raise ValueError("challenge source view cannot be verified") from exc
                if (
                    stat.S_ISLNK(visible_details.st_mode)
                    or not stat.S_ISREG(visible_details.st_mode)
                    or visible_details.st_nlink != 1
                    or visible_details.st_size != details.st_size
                    or not same_file
                ):
                    raise ValueError("challenge source view changed during workspace preparation")
                target.symlink_to(visible)
                staged_inputs.append(ArchiveInput(relative / filename, visible))
            else:
                with item.open("rb") as input_stream, target.open("xb") as output_stream:
                    shutil.copyfileobj(input_stream, output_stream, length=1024 * 1024)
                target.chmod(0o600)
                staged_inputs.append(ArchiveInput(relative / filename, target))
    return tuple(staged_inputs)


def assemble_manual(
    categories: tuple[str, ...],
    *,
    challenge_name: str,
    remote: str = "",
    remote_mode: str | None = None,
    remote_only: bool = False,
    no_server: bool = False,
    remote_access: bool = False,
) -> str:
    """Return the original base manual plus its compact challenge footer."""

    # ``no_server`` is retained for callers from the first isolated-worker
    # release. New job manifests always carry the tri-state value explicitly.
    mode = remote_mode or ("none" if no_server else ("endpoint" if remote else "unknown"))
    if mode not in {"unknown", "none", "endpoint"}:
        raise ValueError("invalid remote mode")
    if (mode == "endpoint") != bool(remote):
        raise ValueError("remote mode and endpoint do not match")

    base = _asset_text("prompts", "base.md").strip()
    tags = ", ".join(f"`{category}`" for category in categories)
    playbooks = ", ".join(f"`../../skills/{category}.md`" for category in categories)
    parts = [
        "<!-- Original ctf_agent operating manual. Base methodology + this "
        "challenge's facts. Category playbooks are in ../../skills/ — open them on "
        "demand. -->",
        base,
    ]
    if remote_only and mode != "none":
        parts.append(_asset_text("prompts", "remote_only.md").strip())
    lines = [
        "---",
        "",
        "## This challenge",
        "",
        f"- Name: `{challenge_name}`",
        f"- Category metadata: {tags}",
        "- Treat category metadata as a triage hint, not a constraint. Infer the actual CTF field from the brief, files, and observed behavior; if evidence conflicts with the label, use the matching playbook instead of forcing the supplied category.",
    ]
    if categories == ("unknown",):
        lines.append(
            "- The supplied category is blank or nonstandard. Start with `../../skills/unknown.md`, identify the most likely field during analysis, then open the relevant category playbook(s)."
        )
        if remote_only and mode == "endpoint" and remote_access:
            lines.append(
                "- Remote-only triage: if the brief and file list do not identify a field, make one bounded banner or protocol probe against the supplied endpoint. Record the response, then choose a playbook. Do not wait for file-based signals that this challenge cannot provide."
            )
    if mode == "none":
        lines.append(
            "- Remote: **none** — there is no server for this challenge. The flag "
            "is obtainable from the given files and the brief alone; do not look for a remote."
        )
    elif mode == "endpoint" and remote_access:
        lines.append(f"- Remote: `{remote}` — use normal clients such as `curl`, `nc`, pwntools, or the challenge-specific solver directly.")
    elif mode == "endpoint":
        lines.append(f"- Remote reference: `{remote}` — network access is disabled for this editorial-only job.")
    else:
        lines.extend(
            (
                "- Remote: **not supplied yet**. This is unknown, not proof that the challenge has no server.",
                "- If an endpoint is required after inspecting the brief and files, first save useful facts and the exact next step in `notes/NEXT.md`, then run `request-remote \"<what endpoint or connection detail is needed>\"` once.",
                "- `request-remote` ends this isolated attempt so the user can update the challenge. Do not start or consume another model turn after calling it.",
            )
        )
    if remote_access:
        lines.append(
            "- Network: direct Internet sockets and DNS are available for challenge solving, dependency retrieval, and public research."
        )
    lines.extend(
        [
            "- Brief: `../chal_desc.md` — read-only; read it first.",
            f"- Category playbooks: shared, read-only `../../skills/` — start with {playbooks} and open others only when triage warrants it.",
            "- Working dir: keep notes in `notes/`, the reproducible exploit in `solver.py`, and scratch output in `tmp/`.",
            "- Tool runtime: for parsers that need a home, cache, or temporary files, create `tmp/{home,cache,temp}` and run them with `HOME=$PWD/tmp/home XDG_CACHE_HOME=$PWD/tmp/cache TMPDIR=$PWD/tmp/temp`; the provider credential home is intentionally inaccessible to commands.",
            "- Select tools from evidence: `apktool` for APK resources and bytecode, `r2`/angr for native binaries, `gdbserver`/pwntools for live pwn debugging, `testdisk`/`photorec` for disk images, `sqlmap` for an observed SQL injection path, and `nmap` for an in-scope network service. Check the category playbook before a large scan or extraction.",
            "- Installed specialist tools when the input warrants them: `ghidra_headless` for native decompilation, `jadx` for APK/DEX/Java source, `pwndbg` for native exploit debugging, `websocat` for interactive WebSockets, `gp` for number theory, `stegseek` for steghide-compatible files, and `multimon-ng` for recorded DTMF/POCSAG signals. Keep project/output files under `tmp/`; Ghidra starts with a 4G Java heap, adjustable via `GHIDRA_HEADLESS_MAXMEM` for a large target.",
            "- If an observed product/version or supplied source points to a public CVE, compare the advisory's preconditions with this target and adapt a public proof of concept only after checking the match. Keep unverified exploit ideas separate from reproduced behavior.",
            "- Browser and emulation: use `ctf-browser --dump-dom <URL>` or `ctf-browser --screenshot=tmp/page.png <URL>` for a headless Chromium session with an ephemeral job-local profile. A requested DevTools port is bound to container loopback. Use QEMU TCG (`qemu-system-x86_64 -accel tcg -nographic -snapshot ...`) when full-system emulation is needed.",
            "- Interactive tools: keep a debugger, REPL, or network session alive across probes when state matters. Use the CLI's persistent terminal if available; otherwise use a job-local tmux socket under `tmp/`, then capture only the relevant pane lines. Do not reconnect and lose state between every step.",
            "- Raw uploads remain unchanged under `attachments/`; safely prepared archive contents are under `extracted/` and listed in `../chal_desc.md`.",
            "- Write `notes/ANALYSIS.md`, `notes/VULN.md`, and `notes/NEXT.md` at the end of each solve cycle.",
            "- In `notes/NEXT.md`, separate observed facts, untested hypotheses, and ruled-out hypotheses. Record the exact control and changed input for each decisive experiment; an error or timeout alone does not rule out a candidate.",
            "- After proving a useful primitive, map the remaining links to the flag and test the nearest missing link first. Derive bounded candidate probes from observed interfaces, files, formats, and behavior; a short list of guessed names is not evidence that no implementation exists.",
            "- For stateful remote services, keep control requests in independent test identities or sessions. If concurrency is not the hypothesis under test, avoid overlapping requests that share state; if it is, record the baseline and concurrent result separately. Before declaring the service unavailable, compare a normal control request and a fresh session with bounded retries.",
            "- When the real flag is verified, run `submit-flag \"<flag>\"`; the worker records that command as the authoritative result handoff.",
            "- Flag discovery ends this turn. A separate turn writes the final Notion-ready write-up.",
        ]
    )
    parts.append("\n".join(lines))
    return "\n\n".join(parts) + "\n"


def prepare_agent_workspace(
    job_root: Path,
    source: Path,
    *,
    challenge_name: str,
    challenge_text: str,
    category: str = "",
    flag_format: str = "",
    remote: str = "",
    remote_mode: str | None = None,
    remote_access: bool = False,
    readonly_source_view: Path | None = None,
    archive_policy: ArchivePolicy | None = None,
) -> PreparedAgentWorkspace:
    """Create the original competition/challenge/workdir topology for one job."""

    if any(_CONTROL.search(value) for value in (challenge_name, challenge_text, category, flag_format, remote) if value):
        raise ValueError("challenge metadata contains control characters")
    remote_mode = remote_mode or ("endpoint" if remote else "unknown")
    if remote_mode not in {"unknown", "none", "endpoint"} or ((remote_mode == "endpoint") != bool(remote)):
        raise ValueError("remote mode and endpoint do not match")
    competition = job_root / "competition"
    challenge_dir = competition / "challenge"
    workdir = challenge_dir / "codex-workdir"
    skills = competition / "skills"
    workdir.mkdir(parents=True, mode=0o700)
    skills.mkdir(mode=0o700)
    categories = normalize_categories(category)
    for item in CATEGORIES:
        _write_readonly(skills / f"{item}.md", _asset_text("prompts", f"skill_{item}.md"))
    _write_readonly(skills / "remote_only.md", _asset_text("prompts", "remote_only.md"))

    brief = challenge_dir / "chal_desc.md"
    try:
        remote_only = not any(source.iterdir())
    except OSError as exc:
        raise ValueError("challenge source cannot be inspected") from exc
    manual = assemble_manual(
        categories,
        challenge_name=challenge_name,
        remote=remote,
        remote_mode=remote_mode,
        remote_only=remote_only,
        remote_access=remote_access,
    )
    # Preserve both providers' native project-manual discovery.  The content is
    # identical so Codex and Claude solve under the same original methodology.
    _write_readonly(workdir / "AGENTS.md", manual)
    _write_readonly(workdir / "CLAUDE.md", manual)
    notes = workdir / "notes"
    notes.mkdir(mode=0o700)
    for name in SCAFFOLDS:
        text = _asset_text("scaffolds", name).replace("{{CHAL}}", challenge_name)
        (notes / name).write_text(text.rstrip("\n") + "\n", encoding="utf-8")
    (workdir / "tmp").mkdir(mode=0o700)
    staged_inputs = _copy_regular_tree(
        source,
        workdir,
        readonly_source_view=readonly_source_view,
    )
    archive_report = extract_attachment_archives(
        workdir,
        staged_inputs,
        policy=archive_policy,
    )
    brief_lines = [f"# {challenge_name}", "", f"Category: {category or 'unknown'}"]
    if flag_format:
        brief_lines.append(f"Flag format: {flag_format}")
    if remote_mode == "endpoint":
        brief_lines.append(f"Remote: {remote}")
    elif remote_mode == "none":
        brief_lines.append("Remote: none (explicitly confirmed)")
    else:
        brief_lines.append("Remote: not supplied yet (unknown)")
    brief_lines.extend(("", "## Description", "", challenge_text))
    prepared_lines = archive_report.brief_lines()
    if prepared_lines:
        brief_lines.extend(("", *prepared_lines))
    _write_readonly(brief, "\n".join(brief_lines))
    return PreparedAgentWorkspace(
        workdir=workdir,
        brief=brief,
        skills=skills,
        archive_report=archive_report,
    )


__all__ = [
    "CATEGORIES",
    "INITIAL_GOAL",
    "NUDGE",
    "POISON_REGOAL",
    "PreparedAgentWorkspace",
    "assemble_manual",
    "normalize_categories",
    "prepare_agent_workspace",
]
