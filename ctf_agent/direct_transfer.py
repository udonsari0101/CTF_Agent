"""One-time, owner-scoped install-to-install workspace transfer.

The target owner creates an invitation in an authenticated browser. A source
installation uses that single capability over HTTPS to stage and import one
existing workspace or challenge ZIP bundle. The receiver never accepts a
source account cookie, and the sender never sends its own account credentials.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets
import sqlite3
import time
import uuid
from contextlib import closing, contextmanager, nullcontext
from pathlib import Path
from typing import Callable, Iterator
from urllib.parse import urlsplit

from fastapi import Body, Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from .db import Settings, connect
from .direct_transfer_client import (
    MAX_BUNDLE_BYTES, DirectTransferClient, DirectTransferClientError,
)
from .direct_transfer_outbox import DirectOutboxError, DirectTransferOutbox
from .process_lock import ProcessFileLock
from .storage_layout import StorageLayout
from .transfer_uploads import CHUNK_BYTES, TransferUploadError, TransferUploadManager
from .workspace_transfer import (
    TransferError, export_challenge, export_workspace, import_challenge,
    import_workspace, lookup_import, preview_bundle,
)


DEFAULT_TTL_SECONDS = 3600
MIN_TTL_SECONDS = 300
MAX_TTL_SECONDS = 24 * 3600
MAX_ACTIVE_INVITATIONS_PER_OWNER = 5
_HEX32 = re.compile(r"[0-9a-f]{32}\Z")
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_BEARER = re.compile(r"Bearer ([A-Za-z0-9_-]{40,128})\Z")


class DirectTransferError(ValueError):
    """Safe API error that contains no invitation token or ZIP content."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _identifier(value: str, label: str) -> str:
    if not isinstance(value, str) or not _HEX32.fullmatch(value):
        raise DirectTransferError("invalid_id", f"Invalid {label}.")
    return value


def _origin(settings: Settings) -> str:
    """Require a configured public HTTPS origin, never a client Host header."""
    value = settings.public_origin
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.netloc or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or parsed.path not in ("", "/") or parsed.query or parsed.fragment):
            raise ValueError("invalid origin")
        _ = parsed.port
    except ValueError as exc:
        raise DirectTransferError(
            "origin_unconfigured", "Configure a public HTTPS origin before creating invitations.",
        ) from exc
    return value.rstrip("/")


class DirectInvitationManager:
    def __init__(self, settings: Settings, uploads: TransferUploadManager,
                 layout: StorageLayout,
                 workspace_lock: Callable[[str], object] | None = None):
        self.settings = settings
        self.uploads = uploads
        self.layout = layout
        self.workspace_lock = workspace_lock or (lambda _workspace_id: nullcontext())
        self.lock_root = Path(settings.config_dir) / ".locks" / "direct_transfer"
        self.lock_root.mkdir(mode=0o700, parents=True, exist_ok=True)
        with closing(connect(settings)) as db, db:
            db.execute(
                """CREATE TABLE IF NOT EXISTS direct_transfer_invitations(
                   id TEXT PRIMARY KEY,
                   token_hash TEXT NOT NULL,
                   owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                   scope TEXT NOT NULL CHECK(scope IN ('workspace','challenge')),
                   destination_workspace_id TEXT,
                   max_size INTEGER NOT NULL,
                   expires_at INTEGER NOT NULL,
                   status TEXT NOT NULL CHECK(status IN
                       ('issued','uploading','completed','revoked','expired')),
                   upload_id TEXT,
                   size INTEGER,
                   sha256 TEXT,
                   result_json TEXT,
                   created_at INTEGER NOT NULL,
                   updated_at INTEGER NOT NULL)"""
            )
            db.execute(
                """CREATE INDEX IF NOT EXISTS idx_direct_transfer_owner
                   ON direct_transfer_invitations(owner_user_id,status,expires_at)"""
            )

    @contextmanager
    def _exclusive(self, invitation_id: str) -> Iterator[None]:
        _identifier(invitation_id, "invitation ID")
        lock = ProcessFileLock(self.lock_root / f"{invitation_id}.lock")
        if not lock.try_acquire():
            raise DirectTransferError("busy", "Invitation is busy; retry shortly.")
        try:
            yield
        finally:
            lock.release()

    @staticmethod
    def _row(db: sqlite3.Connection, invitation_id: str) -> sqlite3.Row:
        row = db.execute(
            """SELECT i.*,u.active AS owner_active FROM direct_transfer_invitations i
               JOIN users u ON u.id=i.owner_user_id WHERE i.id=?""",
            (invitation_id,),
        ).fetchone()
        if row is None:
            raise DirectTransferError("not_found", "Invitation was not found.")
        return row

    @staticmethod
    def _public_status(row: sqlite3.Row) -> dict:
        return {
            "invitation_id": row["id"], "scope": row["scope"],
            "workspace_id": row["destination_workspace_id"],
            "max_size": row["max_size"], "expires_at": row["expires_at"],
            "status": row["status"], "size": row["size"],
            "result": json.loads(row["result_json"]) if row["status"] == "completed" else None,
        }

    @staticmethod
    def _authorize(row: sqlite3.Row, token: str) -> None:
        if (not isinstance(token, str) or not _BEARER.fullmatch(f"Bearer {token}")
                or not hmac.compare_digest(hashlib.sha256(token.encode()).hexdigest(),
                                           row["token_hash"])
                or not row["owner_active"]):
            raise DirectTransferError("unauthorized", "Invitation authorization failed.")

    @staticmethod
    def _live(row: sqlite3.Row) -> None:
        if row["status"] in ("revoked", "expired"):
            raise DirectTransferError("unavailable", "Invitation is no longer available.")
        if row["status"] != "completed" and row["expires_at"] <= int(time.time()):
            raise DirectTransferError("expired", "Invitation has expired.")

    def _authorized_row(self, invitation_id: str, token: str) -> sqlite3.Row:
        _identifier(invitation_id, "invitation ID")
        with closing(connect(self.settings)) as db:
            try:
                row = self._row(db, invitation_id)
            except DirectTransferError as exc:
                if exc.code == "not_found":
                    raise DirectTransferError("unauthorized", "Invitation authorization failed.") from None
                raise
            self._authorize(row, token)
            return row

    def preauthorize(self, invitation_id: str, authorization: str) -> None:
        """Validate bearer before the request-body gate reads a remote chunk."""
        match = _BEARER.fullmatch(authorization)
        if match is None:
            raise DirectTransferError("unauthorized", "Invitation authorization failed.")
        row = self._authorized_row(invitation_id, match.group(1))
        self._live(row)

    def create(self, owner_user_id: str, scope: str,
               destination_workspace_id: str | None, max_size: int,
               ttl_seconds: int = DEFAULT_TTL_SECONDS) -> dict:
        owner = _identifier(owner_user_id, "owner ID")
        if scope not in {"workspace", "challenge"}:
            raise DirectTransferError("invalid_scope", "Transfer scope is invalid.")
        if scope == "challenge":
            destination = _identifier(destination_workspace_id, "destination workspace ID")
        elif destination_workspace_id is not None:
            raise DirectTransferError("invalid_scope", "Workspace transfers create a new workspace.")
        else:
            destination = None
        if type(max_size) is not int or not 0 < max_size <= MAX_BUNDLE_BYTES:
            raise DirectTransferError("invalid_size", "Invitation size must be within the bundle limit.")
        if type(ttl_seconds) is not int or not MIN_TTL_SECONDS <= ttl_seconds <= MAX_TTL_SECONDS:
            raise DirectTransferError("invalid_ttl", "Invitation lifetime is outside the allowed range.")
        origin = _origin(self.settings)
        invitation_id = uuid.uuid4().hex
        token = secrets.token_urlsafe(32)
        now = int(time.time())
        with closing(connect(self.settings)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            if not db.execute("SELECT 1 FROM users WHERE id=? AND active=1", (owner,)).fetchone():
                raise DirectTransferError("owner_inactive", "Invitation owner is inactive.")
            if destination is not None and not db.execute(
                "SELECT 1 FROM workspaces WHERE id=? AND owner_user_id=?",
                (destination, owner),
            ).fetchone():
                raise DirectTransferError("destination_missing", "Destination workspace was not found.")
            active = db.execute(
                """SELECT COUNT(*) FROM direct_transfer_invitations
                   WHERE owner_user_id=? AND status IN ('issued','uploading')
                     AND expires_at>?""",
                (owner, now),
            ).fetchone()[0]
            if active >= MAX_ACTIVE_INVITATIONS_PER_OWNER:
                raise DirectTransferError("owner_limit", "Too many active invitations.")
            db.execute(
                """INSERT INTO direct_transfer_invitations
                   (id,token_hash,owner_user_id,scope,destination_workspace_id,
                    max_size,expires_at,status,created_at,updated_at)
                   VALUES(?,?,?,?,?,?,?,'issued',?,?)""",
                (invitation_id, hashlib.sha256(token.encode()).hexdigest(),
                 owner, scope, destination, max_size, now + ttl_seconds, now, now),
            )
        return {
            "invitation_id": invitation_id, "token": token,
            "url": f"{origin}/api/transfers/direct/invitations/{invitation_id}",
            "scope": scope, "workspace_id": destination,
            "max_size": max_size, "expires_at": now + ttl_seconds,
            "status": "issued",
        }

    def status(self, owner_user_id: str, invitation_id: str) -> dict:
        owner = _identifier(owner_user_id, "owner ID")
        _identifier(invitation_id, "invitation ID")
        with closing(connect(self.settings)) as db:
            row = self._row(db, invitation_id)
            if row["owner_user_id"] != owner:
                raise DirectTransferError("not_found", "Invitation was not found.")
            return self._public_status(row)

    def _progress(self, row: sqlite3.Row) -> dict:
        if row["status"] == "completed":
            return {"status": "completed", "offset": row["size"], "size": row["size"]}
        if row["status"] != "uploading" or not row["upload_id"]:
            raise DirectTransferError("wrong_state", "Invitation is not accepting a bundle.")
        upload = self.uploads.status(row["owner_user_id"], row["upload_id"])
        return {"status": upload["status"], "offset": upload["offset"], "size": upload["size"]}

    def prepare(self, invitation_id: str, token: str, scope: str,
                size: int, sha256: str) -> dict:
        if scope not in {"workspace", "challenge"} or type(size) is not int or size <= 0:
            raise DirectTransferError("invalid_bundle", "Bundle declaration is invalid.")
        if not isinstance(sha256, str) or not _HEX64.fullmatch(sha256):
            raise DirectTransferError("invalid_bundle", "Bundle checksum is invalid.")
        with self._exclusive(invitation_id):
            row = self._authorized_row(invitation_id, token)
            self._live(row)
            if row["scope"] != scope or size > row["max_size"]:
                raise DirectTransferError("scope_mismatch", "Bundle exceeds invitation scope or size.")
            if row["status"] in ("uploading", "completed"):
                if row["size"] != size or row["sha256"] != sha256:
                    raise DirectTransferError("bundle_conflict", "Invitation is bound to another bundle.")
                return self._progress(row)
            if row["status"] != "issued":
                raise DirectTransferError("wrong_state", "Invitation is not accepting a bundle.")
            upload_id = None
            try:
                upload = self.uploads.create(row["owner_user_id"], size, sha256)
                upload_id = upload["upload_id"]
                now = int(time.time())
                with closing(connect(self.settings)) as db, db:
                    db.execute("BEGIN IMMEDIATE")
                    current = self._row(db, invitation_id)
                    self._authorize(current, token)
                    self._live(current)
                    if current["status"] != "issued":
                        raise DirectTransferError("wrong_state", "Invitation changed during preparation.")
                    db.execute(
                        """UPDATE direct_transfer_invitations SET status='uploading',
                           upload_id=?,size=?,sha256=?,updated_at=? WHERE id=?""",
                        (upload_id, size, sha256, now, invitation_id),
                    )
                return {"status": "uploading", "offset": 0, "size": size}
            except BaseException:
                if upload_id is not None:
                    self.uploads.cancel(row["owner_user_id"], upload_id)
                raise

    def append(self, invitation_id: str, token: str, offset: int,
               data: bytes, chunk_sha256: str | None) -> dict:
        row = self._authorized_row(invitation_id, token)
        self._live(row)
        if row["status"] != "uploading" or not row["upload_id"]:
            raise DirectTransferError("wrong_state", "Invitation is not accepting chunks.")
        if chunk_sha256 is None:
            raise DirectTransferError("invalid_digest", "Chunk checksum is required.")
        upload = self.uploads.append(
            row["owner_user_id"], row["upload_id"], offset, data, chunk_sha256,
        )
        return {"status": upload["status"], "offset": upload["offset"], "size": upload["size"]}

    def _finish(self, row: sqlite3.Row, result: dict) -> dict:
        with closing(connect(self.settings)) as db, db:
            db.execute("BEGIN IMMEDIATE")
            current = self._row(db, row["id"])
            if (current["upload_id"] != row["upload_id"]
                    or current["scope"] != row["scope"]
                    or current["destination_workspace_id"] != row["destination_workspace_id"]):
                raise DirectTransferError("wrong_state", "Invitation changed during import.")
            db.execute(
                """UPDATE direct_transfer_invitations SET status='completed',
                   result_json=?,updated_at=? WHERE id=?""",
                (json.dumps(result, separators=(",", ":")), int(time.time()), row["id"]),
            )
        return result

    def complete(self, invitation_id: str, token: str) -> dict:
        with self._exclusive(invitation_id):
            row = self._authorized_row(invitation_id, token)
            if row["status"] == "completed":
                return json.loads(row["result_json"])
            self._live(row)
            if row["status"] != "uploading" or not row["upload_id"]:
                raise DirectTransferError("wrong_state", "Invitation has no bundle to import.")
            owner, upload_id = row["owner_user_id"], row["upload_id"]
            previous = lookup_import(
                self.settings, owner, upload_id, scope=row["scope"],
                destination_workspace_id=row["destination_workspace_id"],
            )
            if previous is not None:
                if self.uploads.status(owner, upload_id)["status"] == "ready":
                    self.uploads.complete(owner, upload_id)
                return self._finish(row, previous)
            self.uploads.finalize(owner, upload_id)
            with self.uploads.import_slot(owner, upload_id) as archive:
                preview = preview_bundle(
                    archive, settings=self.settings, owner_user_id=owner,
                    destination_workspace_id=row["destination_workspace_id"],
                )
                if preview["scope"] != row["scope"]:
                    raise DirectTransferError("scope_mismatch", "Bundle scope does not match invitation.")
                if preview["sufficient_space"] is False:
                    raise DirectTransferError("low_space", "Insufficient space to import the bundle.")
                if row["scope"] == "challenge":
                    workspace_id = row["destination_workspace_id"]
                    with self.workspace_lock(workspace_id):
                        result = import_challenge(
                            self.settings, self.layout, owner, workspace_id, archive,
                            source_upload_id=upload_id,
                        )
                else:
                    result = import_workspace(
                        self.settings, self.layout, owner, archive,
                        source_upload_id=upload_id,
                    )
            return self._finish(row, result)

    def revoke(self, owner_user_id: str, invitation_id: str) -> dict:
        owner = _identifier(owner_user_id, "owner ID")
        with self._exclusive(invitation_id):
            with closing(connect(self.settings)) as db, db:
                db.execute("BEGIN IMMEDIATE")
                row = self._row(db, invitation_id)
                if row["owner_user_id"] != owner:
                    raise DirectTransferError("not_found", "Invitation was not found.")
                if row["status"] == "completed":
                    return self._public_status(row)
                db.execute(
                    "UPDATE direct_transfer_invitations SET status='revoked',updated_at=? WHERE id=?",
                    (int(time.time()), invitation_id),
                )
            if row["upload_id"]:
                try:
                    self.uploads.cancel(owner, row["upload_id"])
                except TransferUploadError as exc:
                    if exc.code not in {"wrong_state", "not_found"}:
                        raise
            return self.status(owner, invitation_id)

    def cleanup_expired(self) -> int:
        """Revoke expired capabilities and reclaim their staged bundles."""
        with closing(connect(self.settings)) as db:
            ids = [row[0] for row in db.execute(
                """SELECT id FROM direct_transfer_invitations
                   WHERE status IN ('issued','uploading') AND expires_at<=?
                   LIMIT 100""",
                (int(time.time()),),
            ).fetchall()]
        cleaned = 0
        for invitation_id in ids:
            try:
                with self._exclusive(invitation_id):
                    with closing(connect(self.settings)) as db, db:
                        db.execute("BEGIN IMMEDIATE")
                        row = self._row(db, invitation_id)
                        if row["status"] not in {"issued", "uploading"} or row["expires_at"] > int(time.time()):
                            continue
                        db.execute(
                            """UPDATE direct_transfer_invitations
                               SET status='expired',updated_at=? WHERE id=?""",
                            (int(time.time()), invitation_id),
                        )
                    if row["upload_id"]:
                        try:
                            self.uploads.cancel(row["owner_user_id"], row["upload_id"])
                        except TransferUploadError as exc:
                            if exc.code not in {"wrong_state", "not_found"}:
                                raise
                    cleaned += 1
            except DirectTransferError as exc:
                if exc.code != "busy":
                    raise
        return cleaned


class InvitationInput(BaseModel):
    scope: str
    workspace_id: str | None = None
    max_size: int = Field(gt=0, le=MAX_BUNDLE_BYTES)
    ttl_seconds: int = Field(default=DEFAULT_TTL_SECONDS,
                             ge=MIN_TTL_SECONDS, le=MAX_TTL_SECONDS)


class PrepareInput(BaseModel):
    scope: str
    size: int = Field(gt=0, le=MAX_BUNDLE_BYTES)
    sha256: str


class SendInput(BaseModel):
    invitation_url: str = Field(max_length=2048)
    token: str = Field(min_length=40, max_length=128, repr=False)
    include_remote: bool = False


def _bearer(request: Request) -> str:
    headers = request.headers.getlist("authorization")
    if len(headers) != 1:
        raise DirectTransferError("unauthorized", "Invitation authorization failed.")
    match = _BEARER.fullmatch(headers[0])
    if match is None:
        raise DirectTransferError("unauthorized", "Invitation authorization failed.")
    return match.group(1)


def register_direct_transfer(app: FastAPI, require_auth, settings: Settings,
                             owner_id: Callable[[], str],
                             require_workspace_owner: Callable[[str, dict], dict]) -> DirectInvitationManager:
    """Register browser and bearer endpoints after app.state.transfer_uploads exists.

    main.py/auth.py must exempt only the three receiver mutation paths from
    cookie/CSRF middleware. This module verifies their scoped bearer token.
    """
    manager = DirectInvitationManager(
        settings, app.state.transfer_uploads, app.state.storage_layout,
        app.state.uploads.try_workspace_lock,
    )
    app.state.direct_transfers = manager
    client = DirectTransferClient()
    outbox = DirectTransferOutbox(settings)
    app.state.direct_transfer_outbox = outbox

    def cleanup_stale():
        # Maintenance is bounded and best effort; a stale cleanup problem must
        # not prevent service startup or an otherwise valid transfer.
        try:
            manager.cleanup_expired()
            outbox.cleanup_stale()
        except Exception:
            logging.warning("Direct transfer stale cleanup deferred")

    cleanup_stale()

    @app.exception_handler(DirectTransferError)
    async def direct_transfer_error(_request: Request, exc: DirectTransferError):
        status = {
            "unauthorized": 401, "not_found": 404, "owner_inactive": 403,
            "destination_missing": 404, "expired": 410, "unavailable": 410,
            "busy": 409, "wrong_state": 409, "bundle_conflict": 409,
            "scope_mismatch": 422, "owner_limit": 429, "low_space": 507,
            "origin_unconfigured": 503,
        }.get(exc.code, 400)
        return JSONResponse({"detail": str(exc), "code": exc.code}, status_code=status)

    @app.exception_handler(DirectTransferClientError)
    async def direct_transfer_client_error(_request: Request, exc: DirectTransferClientError):
        status = 422 if exc.code in {"invalid_url", "invalid_token", "invalid_scope", "blocked_host",
                                      "blocked_address", "invalid_bundle"} else 502
        return JSONResponse({"detail": str(exc), "code": exc.code}, status_code=status)

    @app.exception_handler(DirectOutboxError)
    async def direct_outbox_error(_request: Request, exc: DirectOutboxError):
        status = {
            "busy": 409, "completed": 409, "owner_limit": 429,
            "outbox_full": 507, "source_missing": 404,
            "owner_inactive": 403, "expired": 410,
            "missing_snapshot": 409, "changed_snapshot": 409,
        }.get(exc.code, 400)
        return JSONResponse({"detail": str(exc), "code": exc.code}, status_code=status)

    @app.post("/api/transfers/direct/invitations", status_code=201,
              dependencies=[Depends(require_auth)])
    def create_invitation(payload: InvitationInput):
        cleanup_stale()
        return manager.create(owner_id(), payload.scope, payload.workspace_id,
                              payload.max_size, payload.ttl_seconds)

    @app.get("/api/transfers/direct/invitations/{invitation_id}",
             dependencies=[Depends(require_auth)])
    def invitation_status(invitation_id: str):
        return manager.status(owner_id(), invitation_id)

    @app.delete("/api/transfers/direct/invitations/{invitation_id}",
                dependencies=[Depends(require_auth)])
    def revoke_invitation(invitation_id: str):
        return manager.revoke(owner_id(), invitation_id)

    @app.post("/api/transfers/direct/invitations/{invitation_id}/prepare")
    def prepare_invitation(invitation_id: str, payload: PrepareInput, request: Request):
        return manager.prepare(invitation_id, _bearer(request),
                               payload.scope, payload.size, payload.sha256)

    @app.put("/api/transfers/direct/invitations/{invitation_id}/chunks")
    def receive_chunk(invitation_id: str, request: Request, offset: int,
                      content: bytes = Body(media_type="application/octet-stream"),
                      chunk_sha256: str | None = Header(default=None, alias="X-Chunk-SHA256")):
        return manager.append(invitation_id, _bearer(request), offset, content, chunk_sha256)

    @app.post("/api/transfers/direct/invitations/{invitation_id}/complete")
    def complete_invitation(invitation_id: str, request: Request):
        return manager.complete(invitation_id, _bearer(request))

    def send(workspace_id: str, challenge_id: str | None, payload: SendInput,
             request: Request):
        user = request.state.user
        require_workspace_owner(workspace_id, user)
        client.validate_invitation(payload.invitation_url, payload.token)
        cleanup_stale()
        try:
            with outbox.slot(owner_id(), workspace_id, challenge_id,
                             payload.invitation_url, payload.token,
                             payload.include_remote) as (outbox_id, archive, new_export):
                if new_export:
                    with app.state.uploads.try_workspace_lock(workspace_id):
                        if challenge_id is None:
                            export_workspace(
                                settings, app.state.storage_layout, owner_id(), workspace_id,
                                archive, include_remote=payload.include_remote,
                            )
                        else:
                            export_challenge(
                                settings, app.state.storage_layout, owner_id(), workspace_id,
                                challenge_id, archive, include_remote=payload.include_remote,
                            )
                    outbox.publish(outbox_id, archive)
                result = client.send_bundle(
                    payload.invitation_url, payload.token, archive,
                    scope="workspace" if challenge_id is None else "challenge",
                )
                outbox.complete(outbox_id, archive)
                return result
        except TransferError as exc:
            raise HTTPException(422, str(exc)) from None

    @app.post("/api/workspaces/{workspace_id}/transfer/direct",
              dependencies=[Depends(require_auth)])
    def send_workspace(workspace_id: str, payload: SendInput, request: Request):
        return send(workspace_id, None, payload, request)

    @app.post("/api/workspaces/{workspace_id}/challenges/{challenge_id}/transfer/direct",
              dependencies=[Depends(require_auth)])
    def send_challenge(workspace_id: str, challenge_id: str,
                       payload: SendInput, request: Request):
        return send(workspace_id, challenge_id, payload, request)

    return manager
