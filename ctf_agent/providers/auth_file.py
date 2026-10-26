"""Bounded Codex auth.json import into one owned account, with rollback."""

import json
import os
import shutil
import uuid
from pathlib import Path

from .codex import ProviderError

MAX_AUTH_BYTES = 2 * 1024 * 1024


def validate_auth_file(raw: bytes) -> bytes:
    if not raw or len(raw) > MAX_AUTH_BYTES:
        raise ProviderError("auth.json은 비어 있지 않은 2MiB 이하 파일이어야 합니다.", "invalid_auth_file", stage="auth")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError("duplicate key")
            result[key] = value
        return result
    def constant(_value):
        raise ValueError("non-JSON constant")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant)
        if not isinstance(value, dict):
            raise ValueError("object required")
        if set(value) - {"auth_mode", "OPENAI_API_KEY", "tokens", "last_refresh"}:
            raise ValueError("unrecognized auth format")
        key, tokens = value.get("OPENAI_API_KEY"), value.get("tokens")
        def token(item):
            return isinstance(item, str) and 0 < len(item) <= 131072 and not any(ord(char) < 33 for char in item)
        api_key = token(key)
        chatgpt = isinstance(tokens, dict) and all(token(tokens.get(name)) for name in ("id_token", "access_token", "refresh_token"))
        if api_key == chatgpt or (key is not None and not api_key):
            raise ValueError("authentication structure required")
        if tokens is not None and not chatgpt:
            raise ValueError("invalid tokens")
        if chatgpt and tokens.get("account_id") is not None and not token(tokens["account_id"]):
            raise ValueError("invalid account id")
        for name in ("auth_mode", "last_refresh"):
            if value.get(name) is not None and (not isinstance(value[name], str) or len(value[name]) > 128):
                raise ValueError("invalid metadata")
        return json.dumps(value, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("utf-8")
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise ProviderError("Codex auth.json 형식을 확인해 주세요. 원본 인증 파일을 선택해야 합니다.", "invalid_auth_file", stage="auth") from None


def private_file(path: Path, content: bytes):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(content)
        stream.flush()
        os.fsync(stream.fileno())
    path.chmod(0o600)


async def install_auth_file(adapter, validated: bytes, accounts_root: Path, save_snapshot=None):
    account_home = adapter.home
    directory = account_home / "codex"
    target = directory / "auth.json"
    if (account_home.is_symlink() or directory.is_symlink() or target.is_symlink()
            or account_home.resolve().parent != accounts_root.resolve()
            or directory.resolve().parent != account_home.resolve()):
        raise ProviderError("계정 인증 저장 경로를 확인할 수 없습니다.", "invalid_auth_path", stage="auth")
    await adapter.cancel_login()
    await adapter.close()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    directory.chmod(0o700)
    temporary = directory / f".auth-upload-{uuid.uuid4().hex}.tmp"
    backup = directory / f".auth-previous-{uuid.uuid4().hex}.bak"
    replaced = False
    cleanup_backup = False
    had_previous = target.exists()
    try:
        private_file(temporary, validated)
        if had_previous:
            # Read only this application's selected account; never the host's Codex home.
            descriptor = os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as output, target.open("rb") as original:
                shutil.copyfileobj(original, output)
                output.flush()
                os.fsync(output.fileno())
            backup.chmod(0o600)
        os.replace(temporary, target)
        replaced = True
        result = await adapter.request("account/read", {"refreshToken": False})
        if not isinstance(result.get("account"), dict) or not result["account"]:
            raise ProviderError("업로드한 파일로 Codex 계정을 확인하지 못했습니다.", "auth_required", stage="auth")
        snapshot = await adapter.snapshot()
        if snapshot.get("status") != "authenticated":
            raise ProviderError("업로드한 인증 정보를 확인하지 못했습니다.", "auth_required", stage="auth")
        await adapter.close()
        target.chmod(0o600)
        if save_snapshot:
            save_snapshot(snapshot)
        cleanup_backup = True
        return snapshot
    except BaseException:
        try:
            await adapter.close()
        finally:
            if replaced:
                if had_previous:
                    os.replace(backup, target)
                    target.chmod(0o600)
                else:
                    target.unlink(missing_ok=True)
            cleanup_backup = True
        raise
    finally:
        temporary.unlink(missing_ok=True)
        if cleanup_backup:
            backup.unlink(missing_ok=True)
