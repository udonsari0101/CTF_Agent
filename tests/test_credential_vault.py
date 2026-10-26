"""Credential vault properties: authenticated data and safe key creation."""

import os
import stat
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from ctf_agent.credential_vault import CredentialVault, CredentialVaultError


def settings(tmp_path):
    return SimpleNamespace(config_dir=tmp_path / "config")


def test_round_trip_uses_private_key_and_does_not_expose_plaintext(tmp_path):
    vault = CredentialVault(settings(tmp_path))
    credentials = {
        "method": "password",
        "username": "test-user",
        "password": "never-store-this-in-plain-text",
        "metadata": {"retry": False, "ports": [443, 5050]},
    }

    encrypted = vault.encrypt(credentials, scope="user-1/workspace-1")

    assert encrypted.startswith("ctfv1.")
    assert credentials["password"] not in encrypted
    assert credentials["username"] not in encrypted
    assert vault.decrypt(encrypted, scope="user-1/workspace-1") == credentials
    key_path = settings(tmp_path).config_dir / CredentialVault.KEY_FILENAME
    assert len(key_path.read_bytes()) == 44
    if os.name == "posix":
        assert stat.S_IMODE(key_path.stat().st_mode) & 0o077 == 0


def test_existing_key_survives_restart_and_ciphertexts_are_randomized(tmp_path):
    configured = settings(tmp_path)
    first = CredentialVault(configured)
    one = first.encrypt({"token": "secret"}, scope="workspace-a")
    two = first.encrypt({"token": "secret"}, scope="workspace-a")
    original_key = first.key_path.read_bytes()

    restarted = CredentialVault(configured)

    assert one != two
    assert restarted.key_path.read_bytes() == original_key
    assert restarted.decrypt(one, scope="workspace-a") == {"token": "secret"}
    assert restarted.decrypt(two, scope="workspace-a") == {"token": "secret"}


def test_tampering_wrong_scope_and_wrong_key_have_non_secret_errors(tmp_path):
    secret = "credential-value-that-must-not-leak"
    encrypted = CredentialVault(settings(tmp_path / "one")).encrypt({"password": secret}, scope="owner/a")
    variants = [
        (CredentialVault(settings(tmp_path / "one")), encrypted[:-1] + ("A" if encrypted[-1] != "A" else "B"), "owner/a"),
        (CredentialVault(settings(tmp_path / "one")), encrypted, "owner/b"),
        (CredentialVault(settings(tmp_path / "two")), encrypted, "owner/a"),
    ]

    for vault, value, scope in variants:
        with pytest.raises(CredentialVaultError) as failure:
            vault.decrypt(value, scope=scope)
        assert secret not in str(failure.value)
        assert encrypted not in str(failure.value)
        assert str(failure.value) == "Credential data could not be decrypted."


def test_concurrent_first_use_creates_one_complete_key(tmp_path):
    configured = settings(tmp_path)

    def make(index):
        vault = CredentialVault(configured)
        return vault.encrypt({"worker": index}, scope="shared")

    with ThreadPoolExecutor(max_workers=24) as workers:
        ciphertexts = list(workers.map(make, range(96)))

    vault = CredentialVault(configured)
    assert len(vault.key_path.read_bytes()) == 44
    assert [vault.decrypt(value, scope="shared")["worker"] for value in ciphertexts] == list(range(96))


@pytest.mark.parametrize(
    "credentials",
    [
        {1: "non-string-key"},
        {"bytes": b"not-json"},
        {"nan": float("nan")},
        {"infinity": float("inf")},
        {"tuple": (1, 2)},
        ["top-level-list"],
    ],
)
def test_non_json_values_are_rejected_without_echoing_input(tmp_path, credentials):
    vault = CredentialVault(settings(tmp_path))
    with pytest.raises(CredentialVaultError) as failure:
        vault.encrypt(credentials)
    assert str(failure.value) == "Credential payload is invalid."


def test_recursive_payload_is_rejected(tmp_path):
    recursive = {}
    recursive["self"] = recursive
    with pytest.raises(CredentialVaultError):
        CredentialVault(settings(tmp_path)).encrypt(recursive)


def test_invalid_existing_key_fails_closed(tmp_path):
    configured = settings(tmp_path)
    configured.config_dir.mkdir(parents=True)
    key_path = configured.config_dir / CredentialVault.KEY_FILENAME
    key_path.write_bytes(b"not-a-key")

    with pytest.raises(CredentialVaultError) as failure:
        CredentialVault(configured)

    assert str(failure.value) == "Credential vault key is invalid."
    assert key_path.read_bytes() == b"not-a-key"


@pytest.mark.skipif(not hasattr(os, "symlink"), reason="symlinks are unavailable")
def test_symlink_key_is_never_followed(tmp_path):
    configured = settings(tmp_path)
    configured.config_dir.mkdir(parents=True)
    outside = tmp_path / "outside.key"
    outside.write_bytes(b"x" * 44)
    try:
        os.symlink(outside, configured.config_dir / CredentialVault.KEY_FILENAME)
    except OSError:
        pytest.skip("creating symlinks is not permitted")

    with pytest.raises(CredentialVaultError):
        CredentialVault(configured)
    assert outside.read_bytes() == b"x" * 44
