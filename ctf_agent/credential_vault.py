"""Authenticated, process-safe storage for provider credentials.

Only encrypted strings belong in the database.  The master key is kept in the
application config volume and is never exposed through this module's errors.
"""

from __future__ import annotations

import errno
import hmac
import json
import math
import os
import stat
import time
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken


class CredentialVaultError(RuntimeError):
    """A credential payload or vault key could not be used safely."""


class CredentialVault:
    """Encrypt JSON credentials with one master key from ``settings.config_dir``.

    ``scope`` should identify the owning user and workspace.  It is included
    inside the authenticated envelope, so copying a database ciphertext to a
    different workspace does not make it usable there.
    """

    KEY_FILENAME = "credential-vault.key"
    TOKEN_PREFIX = "ctfv1."
    _KEY_BYTES = 44  # URL-safe base64 encoding of a 32-byte Fernet key.
    _READ_ATTEMPTS = 200
    _READ_DELAY_SECONDS = 0.005

    def __init__(self, settings: Any):
        self.config_dir = Path(settings.config_dir)
        self.key_path = self.config_dir / self.KEY_FILENAME
        self._fernet = Fernet(self._load_or_create_key())

    def encrypt(self, credentials: dict[str, Any], *, scope: str = "") -> str:
        """Return an authenticated ciphertext for a JSON credential mapping."""

        normalized_scope = self._valid_scope(scope)
        try:
            if not isinstance(credentials, dict):
                raise ValueError
            self._validate_json(credentials)
            serialized = json.dumps(
                {"credentials": credentials, "scope": normalized_scope, "version": 1},
                allow_nan=False,
                ensure_ascii=False,
                separators=(",", ":"),
                sort_keys=True,
            ).encode("utf-8")
        except (TypeError, ValueError, OverflowError, RecursionError):
            raise CredentialVaultError("Credential payload is invalid.") from None
        return self.TOKEN_PREFIX + self._fernet.encrypt(serialized).decode("ascii")

    def decrypt(self, ciphertext: str, *, scope: str = "") -> dict[str, Any]:
        """Decrypt and validate a credential mapping for the requested scope."""

        normalized_scope = self._valid_scope(scope)
        try:
            if not isinstance(ciphertext, str) or not ciphertext.startswith(self.TOKEN_PREFIX):
                raise ValueError
            token = ciphertext[len(self.TOKEN_PREFIX) :].encode("ascii")
            raw = self._fernet.decrypt(token)
            envelope = json.loads(raw.decode("utf-8"))
            if not isinstance(envelope, dict) or set(envelope) != {"credentials", "scope", "version"}:
                raise ValueError
            if envelope["version"] != 1 or not isinstance(envelope["scope"], str):
                raise ValueError
            if not hmac.compare_digest(envelope["scope"], normalized_scope):
                raise ValueError
            credentials = envelope["credentials"]
            self._validate_json(credentials)
            if not isinstance(credentials, dict):
                raise ValueError
            return credentials
        except (InvalidToken, UnicodeError, json.JSONDecodeError, TypeError, ValueError, RecursionError):
            raise CredentialVaultError("Credential data could not be decrypted.") from None

    @staticmethod
    def _valid_scope(scope: str) -> str:
        if not isinstance(scope, str) or len(scope) > 1024 or any(ord(character) < 32 for character in scope):
            raise CredentialVaultError("Credential scope is invalid.")
        return scope

    @classmethod
    def _validate_json(cls, value: Any, active: set[int] | None = None) -> None:
        """Reject values that JSON would coerce or serialize inconsistently."""

        if value is None or isinstance(value, (str, bool, int)):
            return
        if isinstance(value, float):
            if not math.isfinite(value):
                raise ValueError
            return
        if active is None:
            active = set()
        if isinstance(value, list):
            identity = id(value)
            if identity in active:
                raise ValueError
            active.add(identity)
            try:
                for item in value:
                    cls._validate_json(item, active)
            finally:
                active.remove(identity)
            return
        if isinstance(value, dict):
            identity = id(value)
            if identity in active:
                raise ValueError
            active.add(identity)
            try:
                for key, item in value.items():
                    if not isinstance(key, str):
                        raise ValueError
                    cls._validate_json(item, active)
            finally:
                active.remove(identity)
            return
        raise ValueError

    def _load_or_create_key(self) -> bytes:
        self.config_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.key_path.is_symlink():
            raise CredentialVaultError("Credential vault key is unavailable.")
        candidate = Fernet.generate_key()
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.key_path, flags, 0o600)
        except FileExistsError:
            return self._read_existing_key_with_retry()
        except OSError:
            raise CredentialVaultError("Credential vault key is unavailable.") from None

        completed = False
        try:
            if os.name == "posix" and hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            view = memoryview(candidate)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError(errno.EIO, "key write failed")
                view = view[written:]
            os.fsync(descriptor)
            completed = True
        except OSError:
            raise CredentialVaultError("Credential vault key could not be created.") from None
        finally:
            os.close(descriptor)
            if not completed:
                try:
                    self.key_path.unlink()
                except OSError:
                    pass
        self._fsync_config_dir()
        return candidate

    def _read_existing_key_with_retry(self) -> bytes:
        # O_EXCL publishes the filename before its first writer finishes.  A
        # competing process waits for a complete key rather than generating a
        # second one and making existing ciphertext unreadable.
        for attempt in range(self._READ_ATTEMPTS):
            try:
                return self._read_existing_key()
            except (FileNotFoundError, _KeyNotReady):
                if attempt + 1 < self._READ_ATTEMPTS:
                    time.sleep(self._READ_DELAY_SECONDS)
        raise CredentialVaultError("Credential vault key is invalid.")

    def _read_existing_key(self) -> bytes:
        if self.key_path.is_symlink():
            raise CredentialVaultError("Credential vault key is unavailable.")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.key_path, flags)
        except FileNotFoundError:
            raise
        except OSError:
            raise CredentialVaultError("Credential vault key is unavailable.") from None
        try:
            details = os.fstat(descriptor)
            if not stat.S_ISREG(details.st_mode):
                raise CredentialVaultError("Credential vault key is invalid.")
            key = b""
            while len(key) <= self._KEY_BYTES:
                chunk = os.read(descriptor, self._KEY_BYTES + 1 - len(key))
                if not chunk:
                    break
                key += chunk
            if len(key) != self._KEY_BYTES:
                raise _KeyNotReady
            try:
                Fernet(key)
            except (TypeError, ValueError):
                raise CredentialVaultError("Credential vault key is invalid.") from None
            if os.name == "posix" and hasattr(os, "fchmod"):
                try:
                    os.fchmod(descriptor, 0o600)
                except OSError:
                    raise CredentialVaultError("Credential vault key is unavailable.") from None
            return key
        finally:
            os.close(descriptor)

    def _fsync_config_dir(self) -> None:
        directory_flag = getattr(os, "O_DIRECTORY", 0)
        if not directory_flag:
            return
        try:
            descriptor = os.open(self.config_dir, os.O_RDONLY | directory_flag)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
        except OSError:
            # The key file itself has already been fsynced.  Some mounted
            # filesystems do not permit opening or syncing directories.
            pass


class _KeyNotReady(Exception):
    """An O_EXCL creator has published the key path but not all key bytes."""
