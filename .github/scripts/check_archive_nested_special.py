"""Nested OCI-style links must not prevent solving the outer challenge."""

import io
import stat
import sys
import tempfile
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from ctf_agent.archive_workspace import (
    ArchiveInput,
    ArchivePolicy,
    ArchiveSafetyError,
    _extract_attachment_archives_direct,
)


def link_archive() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        info = zipfile.ZipInfo("lib/current")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "lib/v1")
    return output.getvalue()


with tempfile.TemporaryDirectory(prefix="ctf-nested-archive-") as directory:
    root = Path(directory)
    attachment = root / "nested.zip"
    with zipfile.ZipFile(attachment, "w") as archive:
        archive.writestr("README.txt", "ordinary challenge files")
        archive.writestr("image-layer.zip", link_archive())
    report = _extract_attachment_archives_direct(
        root, [ArchiveInput(Path("nested.zip"), attachment)],
        policy=ArchivePolicy(min_free_bytes=0),
    )
    assert [(item.status, item.reason) for item in report.actions] == [
        ("expanded", None), ("skipped", "unsafe_nested_archive_entry")
    ]
    assert (root / "extracted/nested_extracted/README.txt").read_text() == "ordinary challenge files"
    assert (root / "extracted/nested_extracted/image-layer.zip").is_file()
    assert not (root / "extracted/nested_extracted/image-layer_extracted").exists()

with tempfile.TemporaryDirectory(prefix="ctf-unsafe-top-archive-") as directory:
    root = Path(directory)
    attachment = root / "top.zip"
    attachment.write_bytes(link_archive())
    try:
        _extract_attachment_archives_direct(
            root, [ArchiveInput(Path("top.zip"), attachment)],
            policy=ArchivePolicy(min_free_bytes=0),
        )
    except ArchiveSafetyError as error:
        assert error.code == "unsafe_archive_entry"
    else:
        raise AssertionError("Top-level unsafe archive was not refused")

print("PASS: nested special entry is skipped; top-level unsafe entry is refused")
