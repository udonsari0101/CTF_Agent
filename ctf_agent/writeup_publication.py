"""Separate challenge solution material from service-only operations."""

from __future__ import annotations

import ast
import re


# These names are private handoff tools, not part of a challenge solution.
# Do not match generic CTFd APIs: a challenge can legitimately target CTFd.
_INTERNAL_OPERATION = re.compile(
    r"(?i)(?<![A-Za-z0-9_-])(?:submit-flag|request-remote|connect-remote)(?![A-Za-z0-9_-])"
    r"|\bctf[-_ ]agent\b"
    r"|/api/workspaces/[A-Za-z0-9_-]+/ctfd/(?:settings|connection|submissions)\b"
    r"|\bCTFd\s*(?:자동\s*제출|auto[- ]?submit)\b"
)


def contains_internal_operation(text: str) -> bool:
    """Inspect prose, inline code and fenced code without logging contents."""

    return isinstance(text, str) and bool(_INTERNAL_OPERATION.search(text))


def public_solution_notes(notes: str) -> str:
    """Remove lines about the private handoff before the editing model sees them."""

    if not isinstance(notes, str) or not contains_internal_operation(notes):
        return notes
    return "".join(
        line for line in notes.splitlines(keepends=True)
        if not contains_internal_operation(line)
    )


def public_solver_source(source: str) -> str:
    """Keep reproducible Python while omitting private handoff statements.

    For Python, replace the smallest statement containing an internal tool
    call with ``pass``. If a safe, parseable excerpt cannot be made, omit the
    source rather than publish service plumbing as challenge code.
    """

    if not isinstance(source, str) or not contains_internal_operation(source):
        return source
    lines = source.splitlines(keepends=True)
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return ""
    offending = [index for index, line in enumerate(lines, 1)
                 if contains_internal_operation(line)]
    removals: dict[int, int] = {}
    for line_number in offending:
        line = lines[line_number - 1]
        if line.lstrip().startswith("#"):
            removals[line_number] = line_number
            continue
        statements = [
            node for node in ast.walk(tree)
            if isinstance(node, ast.stmt)
            and node.lineno <= line_number <= (node.end_lineno or node.lineno)
        ]
        if not statements:
            return ""
        target = min(statements, key=lambda node: (node.end_lineno or node.lineno) - node.lineno)
        removals[target.lineno] = target.end_lineno or target.lineno
    output: list[str] = []
    index = 1
    while index <= len(lines):
        end = removals.get(index)
        if end is None:
            output.append(lines[index - 1])
            index += 1
            continue
        original = lines[index - 1]
        if not original.lstrip().startswith("#"):
            indentation = original[:len(original) - len(original.lstrip())]
            output.append(f"{indentation}pass\n")
        index = end + 1
    cleaned = "".join(output)
    if contains_internal_operation(cleaned):
        return ""
    try:
        ast.parse(cleaned)
    except SyntaxError:
        return ""
    return cleaned
