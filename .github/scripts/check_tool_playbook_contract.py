"""Offline contract for the core-image tool claims in category playbooks.

The image smoke verifies executable behavior after a build. This test catches
prompt regressions before a multi-GB image has to be built.
"""

from __future__ import annotations

import unittest
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
PROMPTS = ROOT / "ctf_agent" / "agent_assets" / "prompts"


def asset(name: str) -> str:
    return (PROMPTS / name).read_text(encoding="utf-8")


class ToolPlaybookContract(unittest.TestCase):
    def test_installed_fallbacks_match_build_and_smoke(self) -> None:
        dockerfile = (ROOT / "Dockerfile.toolchain").read_text(encoding="utf-8")
        dependencies = (ROOT / "requirements-ctf.txt").read_text(encoding="utf-8")
        smoke = (ROOT / "deploy" / "image-smoke.py").read_text(encoding="utf-8")
        for executable in ("ffuf", "gp", "qemu-x86_64", "ghidra_headless", "jadx", "stegseek"):
            self.assertIn(executable, dockerfile + smoke)
            self.assertIn(executable, smoke, f"{executable} needs image smoke coverage")
        for package in ("fpylll", "owiener", "pwntools", "sympy", "z3-solver", "pillow"):
            self.assertIn(package, dependencies.lower())
        self.assertIn("The image includes", asset("skill_forensics.md"))
        self.assertIn("The image includes", asset("skill_crypto.md"))

    def test_absent_tool_first_steps_are_guarded_or_optional(self) -> None:
        web = asset("skill_web.md")
        self.assertNotIn("/usr/share/wordlists/dirb/common.txt", web)
        self.assertIn("tmp/paths.txt", web)
        self.assertIn("tmp/params.txt", web)
        self.assertIn("No \u0060rockyou.txt\u0060 wordlist is bundled", asset("skill_forensics.md"))

        crypto = asset("skill_crypto.md")
        self.assertNotIn("**First move:** \u0060RsaCtfTool", crypto)
        self.assertIn("SageMath is optional, not preinstalled", crypto)
        self.assertIn("RsaCtfTool\u0060 and \u0060roca-detect\u0060 are optional", crypto)

        pwn = asset("skill_pwn.md")
        self.assertNotIn("qemu-x86_64-static -g", pwn)
        self.assertIn("The image includes pwntools", pwn)
        self.assertIn("seccomp-tools disasm filter.bpf", pwn)
        self.assertIn("may be denied by the container's host seccomp policy", pwn)
        self.assertIn("qemu-x86_64 -g 1234", pwn)

        forensics = asset("skill_forensics.md")
        self.assertIn("command -v zsteg", forensics)
        self.assertIn("optional \u0060bkcrack\u0060", forensics)

        reverse = asset("skill_rev.md")
        self.assertIn("no ILSpy/\u0060ilspycmd\u0060", reverse)
        blockchain = asset("skill_blockchain.md")
        self.assertNotIn("curl -L https://foundry.paradigm.xyz | bash", blockchain)
        self.assertIn("Foundry (\u0060forge\u0060/\u0060cast\u0060/\u0060anvil\u0060) and Python \u0060web3\u0060 are optional", blockchain)
        ai = asset("skill_ai-ml.md")
        self.assertIn("does not pin PyTorch", ai)
        self.assertIn("pickletools.dis", ai)

    def test_flag_and_patch_language_is_conditional(self) -> None:
        base = asset("base.md")
        unknown = asset("skill_unknown.md")
        self.assertNotIn("The real flag is on the remote", base)
        self.assertNotIn("the changed lines are the planted bug", base)
        self.assertNotIn("the changed lines ARE the planted bug", unknown)
        self.assertIn("A genuine Flag can come from a supplied artifact", base)
        self.assertIn("never submit an unverified local value", base)
        self.assertNotIn("never submit a local/placeholder flag", base)
        self.assertIn("does not expose a Docker daemon/socket", base)
        self.assertIn("confirm reachability and behavior", unknown)

    def test_initial_goal_preserves_flag_provenance_across_remote_modes(self) -> None:
        from ctf_agent.agent_workspace import INITIAL_GOAL, assemble_manual

        self.assertIn("Verify the genuine flag", INITIAL_GOAL)
        self.assertIn("a local value may be genuine or a placeholder", INITIAL_GOAL)
        self.assertIn("only when a tactic or tool is needed", INITIAL_GOAL)
        self.assertIn("if a direct artifact or command yields the genuine flag", INITIAL_GOAL)
        self.assertIn("without making an unnecessary script", INITIAL_GOAL)
        self.assertIn("without manufacturing a script", asset("base.md"))
        self.assertIn("If a target endpoint is supplied, check one normal response", asset("skill_web.md"))
        self.assertIn('submit-flag "<flag>"', INITIAL_GOAL)
        self.assertNotIn("The REAL flag is on the remote", INITIAL_GOAL)
        for mode, remote, expected in (
            ("none", "", "Remote: **none (configured)**"),
            ("endpoint", "https://example.invalid/", "Remote: `https://example.invalid/`"),
            ("unknown", "", "Remote: **not supplied yet**"),
        ):
            with self.subTest(mode=mode):
                manual = assemble_manual(
                    ("unknown",), challenge_name="Provenance contract",
                    remote=remote, remote_mode=mode,
                    remote_access=mode == "endpoint",
                )
                combined = INITIAL_GOAL + "\n" + manual
                self.assertIn(expected, combined)
                self.assertNotIn("The REAL flag is on the remote", combined)
                if mode == "none":
                    self.assertIn("do not assume that an endpoint exists", combined)
                elif mode == "unknown":
                    self.assertIn("This is unknown, not proof", combined)
                else:
                    self.assertIn("use normal clients", combined)

    def test_unknown_category_allows_cheap_remote_first_contact(self) -> None:
        unknown = asset("skill_unknown.md")
        remote_only = asset("remote_only.md")
        self.assertNotIn("hit the remote until one category wins", unknown)
        self.assertNotIn("When two independent signals agree", unknown)
        self.assertIn("one protocol-appropriate, non-destructive first contact", unknown)
        self.assertIn("Save the response under `tmp/`", unknown)
        self.assertIn("For a target with no files, follow `../../skills/remote_only.md`", unknown)
        self.assertIn("A category label from the platform is a hint, not a gate", unknown)
        self.assertIn("first contact is one gentle touch", remote_only)

    def test_remote_only_missing_endpoint_does_not_continue_after_request(self) -> None:
        base = asset("base.md")
        remote_only = asset("remote_only.md")
        for prompt in (base, remote_only):
            with self.subTest(prompt=prompt[:32]):
                self.assertIn("request-remote", prompt)
                self.assertIn("stop this attempt", prompt)
        self.assertNotIn("then re-read `../chal_desc.md` for the address they add", remote_only)

    def test_assembled_unknown_manual_respects_remote_mode(self) -> None:
        from ctf_agent.agent_workspace import assemble_manual

        with_remote = assemble_manual(
            ("unknown",), challenge_name="Unclassified",
            remote="https://example.invalid/", remote_mode="endpoint",
            remote_only=True, remote_access=True,
        )
        self.assertIn("one bounded banner or protocol probe", with_remote)
        self.assertIn("first contact is one gentle touch", with_remote)
        self.assertNotIn("hit the remote until one category wins", with_remote)

        without_remote = assemble_manual(
            ("unknown",), challenge_name="Local artifact", remote_mode="none",
            remote_only=False, remote_access=False,
        )
        self.assertIn("Remote: **none (configured)**", without_remote)
        self.assertNotIn("first contact is one gentle touch", without_remote)


if __name__ == "__main__":
    unittest.main()
