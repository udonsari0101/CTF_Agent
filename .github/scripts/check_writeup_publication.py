"""Offline regression checks for public write-up content."""

from __future__ import annotations

import ast
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from ctf_agent.solver import SolverLimits, _validate_writeup
from ctf_agent.solver_worker import (
    _ENGLISH_WRITEUP_SECTIONS,
    _WRITEUP_TEMPLATE_SECTIONS,
    _include_solver_source,
    valid_writeup,
)
from ctf_agent.writeup_publication import (
    contains_internal_operation,
    public_solution_notes,
    public_solver_source,
)

FLAG = "FLAG{verified}"
TITLE = "Example Challenge"


def document(locale: str) -> str:
    if locale == "en":
        headings = _ENGLISH_WRITEUP_SECTIONS
        values = (
            "The challenge verifies a signed document.",
            "This is a web challenge about signature validation.",
            "The document field was reflected without escaping.",
            "A crafted document revealed the verification key.",
            "The following Python code reconstructs the signature.\n\n```python\nprint('signature')\n```",
        )
    else:
        headings = _WRITEUP_TEMPLATE_SECTIONS
        values = (
            "서명된 문서를 검증하는 문제입니다.",
            "서명 검증이 핵심인 웹 문제입니다.",
            "문서 필드가 이스케이프되지 않은 것을 확인했습니다.",
            "조작한 문서로 검증 키를 확인했습니다.",
            "다음 코드로 서명을 재현했습니다.\n\n```python\nprint('signature')\n```",
        )
    parts = [f"# {TITLE}"]
    for heading, value in zip(headings, (*values, f"`{FLAG}`")):
        parts.append(f"## {heading}\n\n{value}")
    return "\n\n".join(parts)


class PublicationTests(unittest.TestCase):
    def test_clean_documents_in_both_languages(self) -> None:
        for locale in ("ko", "en"):
            with self.subTest(locale=locale):
                self.assertTrue(valid_writeup(document(locale), TITLE, FLAG, locale))

    def test_internal_handoff_rejected_in_prose_inline_and_fence(self) -> None:
        for locale in ("ko", "en"):
            base = document(locale)
            for extra in (
                "\nsubmit-flag FLAG{verified}",
                "\n`submit-flag FLAG{verified}`",
                "\n```sh\nsubmit-flag FLAG{verified}\n```",
                "\n# CTF Agent: internal handoff",
                "\nCTFd auto-submit the discovered flag",
            ):
                with self.subTest(locale=locale, extra=extra):
                    candidate = base.replace("print('signature')", "print('signature')" + extra)
                    self.assertFalse(valid_writeup(candidate, TITLE, FLAG, locale))

    def test_public_python_excerpt_preserves_solution(self) -> None:
        source = (
            "def solve():\n"
            "    flag = 'FLAG{verified}'\n"
            "    print(flag)\n"
            "    run('submit-flag', flag)\n"
            "    return flag\n"
        )
        clean = public_solver_source(source)
        self.assertNotIn("submit-flag", clean)
        self.assertIn("print(flag)", clean)
        self.assertIn("return flag", clean)
        ast.parse(clean)
        for locale in ("ko", "en"):
            combined = _include_solver_source(document(locale), clean, locale)
            self.assertIn("return flag", combined)
            self.assertTrue(valid_writeup(combined, TITLE, FLAG, locale))

    def test_unparseable_private_source_is_omitted(self) -> None:
        self.assertEqual(public_solver_source("submit-flag FLAG{verified}\n"), "")

    def test_legitimate_ctfd_target_code_is_not_removed(self) -> None:
        source = "import requests\nresponse = requests.get('https://target/api/v1/challenges')\n"
        self.assertEqual(public_solver_source(source), source)
        self.assertFalse(contains_internal_operation(source))

    def test_private_notes_and_generic_adapter(self) -> None:
        notes = "Found a signing bypass.\nsubmit-flag FLAG{verified}\nReproduced locally.\n"
        self.assertEqual(public_solution_notes(notes), "Found a signing bypass.\nReproduced locally.\n")
        with self.assertRaises(ValueError):
            _validate_writeup("Result: `submit-flag FLAG{verified}`", SolverLimits(), Path("/challenge"))
        self.assertEqual(
            _validate_writeup("Result: the signature verifies.", SolverLimits(), Path("/challenge")),
            "Result: the signature verifies.",
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
