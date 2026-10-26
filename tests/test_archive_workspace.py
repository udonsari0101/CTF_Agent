import bz2
import gzip
import io
import lzma
import os
import stat
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

import ctf_agent.archive_workspace as archive_workspace
from ctf_agent.agent_workspace import prepare_agent_workspace
from ctf_agent.archive_workspace import (
    ArchiveInput,
    ArchivePolicy,
    ArchiveSafetyError,
    MAX_ARCHIVE_OUTPUT_BYTES,
    archive_kind,
    extract_attachment_archives,
)


def zip_bytes(files: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as archive:
        for name, payload in files.items():
            archive.writestr(name, payload)
    return output.getvalue()


def extract_one(tmp_path, name, payload, *, policy=None):
    source = tmp_path / name
    source.write_bytes(payload)
    workdir = tmp_path / f"workdir-{Path(name).stem}"
    workdir.mkdir()
    report = extract_attachment_archives(
        workdir,
        [ArchiveInput(Path("attachments") / name, source)],
        policy=policy,
    )
    return workdir, report


def test_original_zip_and_nested_semantics_preserve_the_raw_attachment(tmp_path):
    inner = zip_bytes({"deep/flag.txt": b"SARI{nested}"})
    outer = zip_bytes({"README.txt": b"inspect inner.zip", "inner.zip": inner})
    source = tmp_path / "source"
    attachments = source / "attachments"
    attachments.mkdir(parents=True)
    raw = attachments / "0001_bundle.zip"
    raw.write_bytes(outer)

    prepared = prepare_agent_workspace(
        tmp_path / "job",
        source,
        challenge_name="Nested bundle",
        challenge_text="Inspect the supplied bundle.",
        category="forensics",
    )

    assert (prepared.workdir / "attachments/0001_bundle.zip").read_bytes() == outer
    expanded = prepared.workdir / "extracted/0001_bundle_extracted"
    assert (expanded / "README.txt").read_bytes() == b"inspect inner.zip"
    assert (expanded / "inner.zip").read_bytes() == inner
    assert (expanded / "inner_extracted/deep/flag.txt").read_bytes() == b"SARI{nested}"
    assert [action.depth for action in prepared.archive_report.expanded] == [0, 1]
    brief = prepared.brief.read_text(encoding="utf-8")
    assert "## Prepared attachments" in brief
    assert "`attachments/0001_bundle.zip`" in brief
    assert "`extracted/0001_bundle_extracted`" in brief


def test_tar_and_single_file_compression_match_original_supported_formats(tmp_path):
    tar_payload = io.BytesIO()
    with tarfile.open(fileobj=tar_payload, mode="w:gz") as archive:
        info = tarfile.TarInfo("tree/value.txt")
        info.size = 3
        archive.addfile(info, io.BytesIO(b"tar"))
    compressed = io.BytesIO()
    with gzip.GzipFile(fileobj=compressed, mode="wb") as archive:
        archive.write(b"single")

    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "bundle.tgz").write_bytes(tar_payload.getvalue())
    (raw / "message.txt.gz").write_bytes(compressed.getvalue())
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    report = extract_attachment_archives(
        workdir,
        [ArchiveInput(Path(path.name), path) for path in raw.iterdir()],
    )

    assert (workdir / "extracted/bundle_extracted/tree/value.txt").read_bytes() == b"tar"
    assert (workdir / "extracted/message.txt_extracted/message.txt").read_bytes() == b"single"
    assert {action.kind for action in report.expanded} == {"tar", "gz"}


def test_nested_gzip_tar_accepts_a_normal_gnu_root_directory_entry(tmp_path):
    """Match the nested image layout used by the production Smart Device challenge."""

    tar_payload = io.BytesIO()
    with tarfile.open(fileobj=tar_payload, mode="w:gz") as archive:
        root = tarfile.TarInfo(".")
        root.type = tarfile.DIRTYPE
        archive.addfile(root)
        directory = tarfile.TarInfo("./etc")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        config = tarfile.TarInfo("./etc/device.conf")
        config.size = len(b"mode=fixture\n")
        archive.addfile(config, io.BytesIO(b"mode=fixture\n"))

    outer = zip_bytes({"smart_device.img": tar_payload.getvalue()})
    workdir, report = extract_one(tmp_path, "smart-device.zip", outer)

    assert (
        workdir
        / "extracted/smart-device_extracted/smart_device_extracted/smart_device_extracted/etc/device.conf"
    ).read_bytes() == b"mode=fixture\n"
    assert [action.kind for action in report.expanded] == ["zip", "gz", "tar"]


def test_tar_root_named_dot_is_only_ignored_when_it_is_a_directory(tmp_path):
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w") as archive:
        root_file = tarfile.TarInfo(".")
        root_file.size = 1
        archive.addfile(root_file, io.BytesIO(b"x"))

    with pytest.raises(ArchiveSafetyError) as caught:
        extract_one(tmp_path, "root-file.tar", payload.getvalue())
    assert caught.value.code == "unsafe_archive_path"


@pytest.mark.parametrize(
    ("name", "compress"),
    [
        ("message.gz", gzip.compress),
        ("message.bz2", bz2.compress),
        ("message.xz", lzma.compress),
    ],
)
def test_all_original_single_file_compressors_are_supported(tmp_path, name, compress):
    workdir, report = extract_one(tmp_path, name, compress(b"decoded"))
    assert (workdir / f"extracted/message_extracted/message").read_bytes() == b"decoded"
    assert report.expanded[0].kind == Path(name).suffix[1:]


@pytest.mark.parametrize(
    ("name", "mode"),
    [
        ("bundle.tar", "w"),
        ("bundle.tar.gz", "w:gz"),
        ("bundle.tar.bz2", "w:bz2"),
        ("bundle.tar.xz", "w:xz"),
    ],
)
def test_all_original_tar_wrappers_are_supported(tmp_path, name, mode):
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode=mode) as archive:
        info = tarfile.TarInfo("value")
        info.size = 2
        archive.addfile(info, io.BytesIO(b"ok"))
    workdir, report = extract_one(tmp_path, name, payload.getvalue())
    target = workdir / f"extracted/{Path(name).stem}_extracted/value"
    assert target.read_bytes() == b"ok"
    assert report.expanded[0].kind == "tar"


@pytest.mark.parametrize("name", ["bundle.zip", "bundle.jar", "bundle.apk", "bundle"])
def test_zip_extensions_and_magic_only_archives_are_detected(tmp_path, name):
    source = tmp_path / name
    source.write_bytes(zip_bytes({"value": b"ok"}))
    assert archive_kind(source) == "zip"


def test_7z_is_expanded_without_using_an_external_path_extractor(tmp_path):
    py7zr = pytest.importorskip("py7zr")
    source = tmp_path / "bundle.7z"
    with py7zr.SevenZipFile(source, "w") as archive:
        archive.writestr(b"seven", "nested/value.txt")

    workdir = tmp_path / "workdir"
    workdir.mkdir()
    report = extract_attachment_archives(
        workdir,
        [ArchiveInput(Path("attachments/bundle.7z"), source)],
    )

    assert (workdir / "extracted/bundle_extracted/nested/value.txt").read_bytes() == b"seven"
    assert report.expanded[0].kind == "7z"


def test_multi_folder_7z_is_streamed_through_bounded_outputs(tmp_path):
    py7zr = pytest.importorskip("py7zr")
    first = tmp_path / "first.bin"
    second = tmp_path / "second.bin"
    first.write_bytes(b"first")
    second.write_bytes(b"second")
    source = tmp_path / "multi.7z"
    with py7zr.SevenZipFile(source, "w") as archive:
        archive.write(first, "first.bin")
    with py7zr.SevenZipFile(source, "a") as archive:
        archive.write(second, "second.bin")

    workdir = tmp_path / "workdir"
    workdir.mkdir()
    report = extract_attachment_archives(
        workdir,
        [ArchiveInput(Path("attachments/multi.7z"), source)],
    )

    assert report.expanded[0].bytes_written == 11
    assert (workdir / "extracted/multi_extracted/first.bin").read_bytes() == b"first"
    assert (workdir / "extracted/multi_extracted/second.bin").read_bytes() == b"second"


@pytest.mark.parametrize("name", ["../escape", "/absolute", "C:/drive", "safe/../../escape"])
def test_zip_path_traversal_and_absolute_paths_refuse_the_job(tmp_path, name):
    payload = zip_bytes({name: b"escape"})
    with pytest.raises(ArchiveSafetyError) as caught:
        extract_one(tmp_path, "unsafe.zip", payload)
    assert caught.value.code == "unsafe_archive_path"
    assert not (tmp_path / "escape").exists()


def test_zip_symlink_is_rejected_before_any_member_is_published(tmp_path):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("first.txt", b"must be rolled back")
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "../../outside")

    with pytest.raises(ArchiveSafetyError) as caught:
        workdir, _ = extract_one(tmp_path, "links.zip", output.getvalue())
    assert caught.value.code == "unsafe_archive_entry"
    assert not (tmp_path / "workdir-links/extracted/links_extracted").exists()


@pytest.mark.parametrize("directory_attribute", [0, 0x10])
def test_windows_zip_directory_entries_are_not_misread_as_unix_special_files(
    tmp_path, directory_attribute
):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        directory = zipfile.ZipInfo("folder/")
        directory.create_system = 0
        directory.external_attr = directory_attribute
        archive.writestr(directory, b"")
        archive.writestr("folder/value.txt", b"windows zip")

    workdir, report = extract_one(tmp_path, "windows.zip", output.getvalue())

    assert (workdir / "extracted/windows_extracted/folder/value.txt").read_bytes() == b"windows zip"
    assert report.expanded[0].kind == "zip"


@pytest.mark.parametrize("create_system", [0, 10])
def test_windows_directory_attribute_works_without_a_trailing_slash(tmp_path, create_system):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        directory = zipfile.ZipInfo("folder")
        directory.create_system = create_system
        directory.external_attr = 0x10
        archive.writestr(directory, b"")
        archive.writestr("folder/value.txt", b"dos zip")

    workdir, report = extract_one(tmp_path, "dos.zip", output.getvalue())

    assert (workdir / "extracted/dos_extracted/folder/value.txt").read_bytes() == b"dos zip"
    assert report.expanded[0].kind == "zip"


def test_policy_defaults_match_disk_backed_ctf_agent_and_optional_caps_validate():
    assert ArchivePolicy().max_output_bytes == 0
    assert ArchivePolicy().max_members == 0
    assert ArchivePolicy().max_seconds == 0
    assert ArchivePolicy().max_compression_ratio == 0
    assert ArchivePolicy().max_memory_bytes == 0
    assert ArchivePolicy(max_output_bytes=1).max_output_bytes == 1
    with pytest.raises(ValueError):
        ArchivePolicy(max_output_bytes=-1)
    with pytest.raises(ValueError):
        ArchivePolicy(max_seconds=-1)


@pytest.mark.parametrize("member_type", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE])
def test_tar_links_and_special_files_are_never_created(tmp_path, member_type):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        member = tarfile.TarInfo("unsafe")
        member.type = member_type
        member.linkname = "../../outside"
        if member_type == tarfile.CHRTYPE:
            member.devmajor = member.devminor = 1
        archive.addfile(member)

    with pytest.raises(ArchiveSafetyError) as caught:
        extract_one(tmp_path, "unsafe.tar", output.getvalue())
    assert caught.value.code == "unsafe_archive_entry"
    assert not (tmp_path / "outside").exists()


def test_casefolded_duplicate_and_file_directory_collisions_remain_raw(tmp_path):
    duplicate = io.BytesIO()
    with zipfile.ZipFile(duplicate, "w") as archive:
        archive.writestr("Dir/File.txt", b"one")
        archive.writestr("dir/file.TXT", b"two")
    workdir, report = extract_one(tmp_path, "duplicate.zip", duplicate.getvalue())
    assert report.actions[0].status == "skipped"
    assert report.actions[0].reason == "unsafe_archive_collision"
    assert not (workdir / "extracted/duplicate_extracted").exists()

    collision = zip_bytes({"parent": b"file", "parent/child": b"child"})
    workdir, report = extract_one(tmp_path, "collision.zip", collision)
    assert report.actions[0].status == "skipped"
    assert report.actions[0].reason == "unsafe_archive_collision"
    assert not (workdir / "extracted/collision_extracted").exists()


def test_colliding_archive_does_not_prevent_an_independent_safe_archive(tmp_path):
    sources = tmp_path / "sources"
    sources.mkdir()
    unsafe = sources / "unsafe.zip"
    safe = sources / "safe.zip"
    duplicate = io.BytesIO()
    with pytest.warns(UserWarning, match="Duplicate name"):
        with zipfile.ZipFile(duplicate, "w") as archive:
            archive.writestr("same.txt", b"one")
            archive.writestr("same.txt", b"two")
    unsafe.write_bytes(duplicate.getvalue())
    safe.write_bytes(zip_bytes({"value.txt": b"usable"}))
    workdir = tmp_path / "workdir"
    workdir.mkdir()

    report = extract_attachment_archives(
        workdir,
        [
            ArchiveInput(Path("attachments/unsafe.zip"), unsafe),
            ArchiveInput(Path("attachments/safe.zip"), safe),
        ],
    )

    actions = {Path(action.source).name: action for action in report.actions}
    assert actions["unsafe.zip"].reason == "unsafe_archive_collision"
    assert actions["safe.zip"].status == "expanded"
    assert (workdir / "extracted/safe_extracted/value.txt").read_bytes() == b"usable"
    assert not (workdir / "extracted/unsafe_extracted").exists()


def test_explicit_output_cap_stops_declared_and_streamed_expansion(tmp_path):
    assert MAX_ARCHIVE_OUTPUT_BYTES == 0
    payload = zip_bytes({"large.bin": b"A" * 65})
    policy = ArchivePolicy(max_output_bytes=64)
    _workdir, report = extract_one(tmp_path, "bomb.zip", payload, policy=policy)
    assert report.actions[0].status == "skipped"
    assert report.actions[0].reason == "archive_expansion_limit"
    assert not (tmp_path / "workdir-bomb/extracted/bomb_extracted").exists()


def test_streamed_expansion_preserves_configured_filesystem_free_space(tmp_path):
    payload = zip_bytes({"value.bin": b"payload"})
    policy = ArchivePolicy(min_free_bytes=2**63 - 1)
    _workdir, report = extract_one(tmp_path, "reserve.zip", payload, policy=policy)
    assert report.actions[0].status == "skipped"
    assert report.actions[0].reason == "archive_scratch_full"
    assert not (tmp_path / "workdir-reserve/extracted/reserve_extracted").exists()


def test_member_count_and_compression_ratio_bombs_are_rejected(tmp_path):
    members = zip_bytes({"one": b"1", "two": b"2"})
    _workdir, report = extract_one(tmp_path, "members.zip", members, policy=ArchivePolicy(max_members=1))
    assert report.actions[0].reason == "archive_member_limit"

    compressed = zip_bytes({"zeros.bin": bytes(50_000)})
    ratio_policy = ArchivePolicy(
        max_output_bytes=100_000,
        max_compression_ratio=2,
        compression_ratio_floor_bytes=1,
    )
    _workdir, report = extract_one(tmp_path, "ratio.zip", compressed, policy=ratio_policy)
    assert report.actions[0].reason == "archive_compression_ratio"


def test_implicit_parent_directories_count_toward_the_member_budget(tmp_path):
    payload = zip_bytes({"one/two/three/value.txt": b"x"})
    _workdir, report = extract_one(
        tmp_path,
        "deep.zip",
        payload,
        policy=ArchivePolicy(max_members=3),
    )
    assert report.actions[0].reason == "archive_member_limit"
    assert not (tmp_path / "workdir-deep/extracted/deep_extracted").exists()


def test_crashed_disposable_extractor_keeps_raw_input_and_clears_output(tmp_path, monkeypatch):
    source = tmp_path / "crash.zip"
    payload = zip_bytes({"value.txt": b"still raw"})
    source.write_bytes(payload)
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    monkeypatch.setattr(
        archive_workspace,
        "_archive_child_command",
        lambda **_kwargs: [
            sys.executable,
            "-c",
            (
                "from pathlib import Path; "
                "Path('extracted/partial').mkdir(parents=True); "
                "Path('extracted/partial/value').write_bytes(b'partial'); "
                "raise SystemExit(9)"
            ),
        ],
    )

    report = extract_attachment_archives(
        workdir,
        [ArchiveInput(Path("attachments/crash.zip"), source)],
    )

    assert report.actions[0].reason == "extractor_crashed"
    assert source.read_bytes() == payload
    assert not (workdir / "extracted").exists()


def test_missing_disposable_extractor_keeps_raw_input_and_reports_safe_skip(tmp_path, monkeypatch):
    source = tmp_path / "isolated.zip"
    payload = zip_bytes({"value.txt": b"still raw"})
    source.write_bytes(payload)
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    monkeypatch.setattr(archive_workspace, "_archive_child_command", lambda **_kwargs: None)

    report = extract_attachment_archives(
        workdir,
        [ArchiveInput(Path("attachments/isolated.zip"), source)],
    )

    assert report.actions[0].reason == "extractor_isolation_unavailable"
    assert source.read_bytes() == payload
    assert not (workdir / "extracted").exists()


def test_unreported_child_output_is_discarded_before_work_continues(tmp_path, monkeypatch):
    source = tmp_path / "invalid.zip"
    payload = zip_bytes({"value.txt": b"still raw"})
    source.write_bytes(payload)
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    script = (
        "import json,sys; from pathlib import Path; "
        "Path('extracted/rogue').mkdir(parents=True); "
        "Path('extracted/rogue/value').write_bytes(b'rogue'); "
        "Path(sys.argv[-1]).write_text(json.dumps({"
        "'protocol':1,'status':'ok','actions':[],'error':None}),encoding='utf-8')"
    )
    monkeypatch.setattr(
        archive_workspace,
        "_archive_child_command",
        lambda **_kwargs: [sys.executable, "-c", script],
    )

    report = extract_attachment_archives(
        workdir,
        [ArchiveInput(Path("attachments/invalid.zip"), source)],
    )

    assert report.actions[0].reason == "extractor_result_invalid"
    assert source.read_bytes() == payload
    assert not (workdir / "extracted").exists()


def test_parent_wall_timeout_kills_extractor_and_keeps_raw_input(tmp_path, monkeypatch):
    source = tmp_path / "slow.zip"
    payload = zip_bytes({"value.txt": b"still raw"})
    source.write_bytes(payload)
    workdir = tmp_path / "workdir"
    workdir.mkdir()
    monkeypatch.setattr(
        archive_workspace,
        "_archive_child_command",
        lambda **_kwargs: [
            sys.executable,
            "-c",
            (
                "import sys,time; from pathlib import Path; "
                "Path('extracted/partial').mkdir(parents=True); "
                "Path('extracted/partial/value').write_bytes(b'partial'); "
                "Path(sys.argv[-1]).write_text('{}',encoding='utf-8'); time.sleep(60)"
            ),
        ],
    )

    report = extract_attachment_archives(
        workdir,
        [ArchiveInput(Path("attachments/slow.zip"), source)],
        policy=ArchivePolicy(max_seconds=0.05),
    )

    assert report.actions[0].reason == "extractor_timeout"
    assert source.read_bytes() == payload
    assert not (workdir / "extracted").exists()
    assert not list(workdir.glob(".archive-result-*"))


def test_nested_expansion_is_bounded_to_the_original_three_nested_layers(tmp_path):
    payload = zip_bytes({"deep.txt": b"end"})
    for level in reversed(range(5)):
        payload = zip_bytes({f"level-{level}.zip": payload})

    workdir, report = extract_one(tmp_path, "root.zip", payload)
    assert [action.depth for action in report.expanded] == [0, 1, 2, 3]
    skipped = [action for action in report.actions if action.reason == "nested_depth_limit"]
    assert len(skipped) == 1 and skipped[0].depth == 4
    assert not any(path.name == "level-3_extracted" for path in workdir.rglob("*"))


def test_corrupt_or_encrypted_archives_remain_raw_and_are_explained_in_the_brief(tmp_path):
    source = tmp_path / "source"
    attachments = source / "attachments"
    attachments.mkdir(parents=True)
    raw = attachments / "0001_broken.zip"
    raw.write_bytes(b"not really a zip")

    prepared = prepare_agent_workspace(
        tmp_path / "job",
        source,
        challenge_name="Broken archive",
        challenge_text="The malformed header may be intentional.",
    )

    assert (prepared.workdir / "attachments/0001_broken.zip").read_bytes() == raw.read_bytes()
    assert prepared.archive_report.actions[0].status == "skipped"
    assert prepared.archive_report.actions[0].reason == "invalid_or_unsupported_archive"
    assert "use the raw file if needed" in prepared.brief.read_text(encoding="utf-8")


@pytest.mark.skipif(os.name == "nt", reason="Windows CI accounts may not create symlinks")
def test_readonly_source_view_keeps_raw_archive_zero_copy_while_only_expansion_uses_scratch(tmp_path):
    source = tmp_path / "exchange/active/challenge"
    attachments = source / "attachments"
    attachments.mkdir(parents=True)
    raw = attachments / "0001_small.zip"
    raw.write_bytes(zip_bytes({"payload.bin": b"payload"}))

    prepared = prepare_agent_workspace(
        tmp_path / "job",
        source,
        readonly_source_view=source,
        challenge_name="Read-only archive",
        challenge_text="Inspect it.",
    )

    linked = prepared.workdir / "attachments/0001_small.zip"
    assert linked.is_symlink() and os.path.samefile(linked, raw)
    assert (prepared.workdir / "extracted/0001_small_extracted/payload.bin").read_bytes() == b"payload"
