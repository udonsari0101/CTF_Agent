"""Shared disk accounting for manual and install-to-install ZIP exports."""

from __future__ import annotations

import stat
from contextlib import closing
from pathlib import Path

from .db import Settings, connect
from .direct_transfer_client import MAX_BUNDLE_BYTES
from .solver_history_transfer import HistoryError, history_digest
from .storage_budget import MAX_SQLITE_INTEGER, StorageBudget
from .storage_layout import StorageLayout
from .transfer_uploads import MIN_FREE_BYTES
from .workspace_transfer import (
    MAX_ENTRIES, MAX_MANIFEST_BYTES, TransferError, _source_metadata,
    _sync_readable, export_challenge, export_workspace,
)


EXPORT_ENTRY_OVERHEAD = 1024
EXPORT_FIXED_OVERHEAD = 1024 * 1024
MANUAL_RESERVATION_KIND = "manual_export"


def estimate_bundle_bytes(settings: Settings, layout: StorageLayout,
                          owner: str, workspace_id: str,
                          challenge_id: str | None) -> int:
    """Conservatively bound ZIP64 output before writing to the data volume.

    One percent expansion plus 1 KiB per entry covers DEFLATE's worst-case
    overhead and ZIP64 headers. The manifest has a separate 16 MiB cap.
    """
    _sync_readable(settings, layout, owner, workspace_id, challenge_id)
    snapshot = _source_metadata(settings, owner, workspace_id)
    attachments = snapshot["attachments"]
    if challenge_id is not None:
        if not any(item["id"] == challenge_id for item in snapshot["challenges"]):
            raise TransferError("Challenge not found in this workspace.")
        attachments = [item for item in attachments if item["challenge_id"] == challenge_id]
    if len(attachments) > MAX_ENTRIES:
        raise TransferError("Too many attachments for one bundle.")
    try:
        with closing(connect(settings)) as db:
            history_bytes = history_digest(db, owner, workspace_id, challenge_id)["size"]
    except HistoryError as exc:
        raise TransferError(str(exc)) from exc
    uncompressed = sum(item["size"] for item in attachments) + history_bytes
    estimated = (uncompressed + (uncompressed + 99) // 100
                 + MAX_MANIFEST_BYTES
                 + (len(attachments) + 2) * EXPORT_ENTRY_OVERHEAD
                 + EXPORT_FIXED_OVERHEAD)
    if estimated > min(MAX_BUNDLE_BYTES, MAX_SQLITE_INTEGER):
        raise TransferError("Export is too large for the transfer protocol.")
    return estimated


def reserve_bundle_bytes(budget: StorageBudget, key: str, kind: str,
                         owner: str, workspace_id: str,
                         challenge_id: str | None, estimate: int) -> None:
    # Publication requires 5 GiB free. Include any headroom above the shared
    # budget's configured floor in the reservation, without a long-held lock.
    headroom = max(0, MIN_FREE_BYTES - budget.minimum_free_bytes)
    if estimate + headroom > MAX_SQLITE_INTEGER:
        raise TransferError("Export is too large for the data volume.")
    budget.reserve(key, kind, owner, workspace_id, challenge_id,
                   estimate + headroom)


def _regular_unlink(path: Path) -> None:
    try:
        details = path.lstat()
    except FileNotFoundError:
        return
    if not stat.S_ISREG(details.st_mode):
        raise TransferError("Source snapshot path is invalid.")
    path.unlink()


def remove_partial_export(destination: Path) -> None:
    """Remove a failed ZIP and crash-left staging files before releasing bytes."""
    destination = Path(destination)
    _regular_unlink(destination)
    for staging in destination.parent.glob(f".{destination.name}.*.tmp"):
        _regular_unlink(staging)


def export_manual_bundle(settings: Settings, layout: StorageLayout,
                         budget: StorageBudget, owner: str,
                         workspace_id: str, challenge_id: str | None,
                         destination: Path, *, include_remote: bool = False) -> dict:
    """Export a manual download with the same cross-process budget as direct send.

    Caller holds its per-export lock and the workspace write lock. On failure,
    partial bytes are removed before the reservation is released. A process
    crash leaves the reservation for TransferExportManager's lock-based sweep.
    """
    destination = Path(destination)
    if not destination.stem or len(destination.stem) != 32 or any(
        char not in "0123456789abcdef" for char in destination.stem
    ):
        raise TransferError("Invalid export destination.")
    key = f"manual-export:{destination.stem}"
    estimate = estimate_bundle_bytes(settings, layout, owner,
                                     workspace_id, challenge_id)
    reserve_bundle_bytes(budget, key, MANUAL_RESERVATION_KIND,
                         owner, workspace_id, challenge_id, estimate)
    try:
        if challenge_id is None:
            result = export_workspace(settings, layout, owner,
                                      workspace_id, destination,
                                      include_remote=include_remote)
        else:
            result = export_challenge(settings, layout, owner,
                                      workspace_id, challenge_id, destination,
                                      include_remote=include_remote)
        if destination.stat().st_size > estimate:
            raise TransferError("Export exceeded its reserved size.")
    except BaseException:
        budget.release(key, cleanup=lambda: remove_partial_export(destination))
        raise
    budget.release(key)
    return result
