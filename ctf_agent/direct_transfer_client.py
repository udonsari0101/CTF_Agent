"""HTTPS-only, DNS-pinned sender for a one-time workspace invitation.

No local session cookie or account credential is sent. The only outbound
authorization value is the receiver's scoped invitation token. Redirects,
environment proxies, private addresses, and non-transfer URL paths are denied.
"""

from __future__ import annotations

import hashlib
import http.client
import ipaddress
import json
import os
import re
import socket
import ssl
import stat
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

from .transfer_uploads import CHUNK_BYTES


MAX_BUNDLE_BYTES = 20 * 1024**3
MAX_RESPONSE_BYTES = 64 * 1024
REQUEST_TIMEOUT_SECONDS = 45
TRANSFER_DEADLINE_SECONDS = 24 * 3600
INVITATION_PATH = re.compile(r"/api/transfers/direct/invitations/[0-9a-f]{32}\Z")
_TOKEN = re.compile(r"[A-Za-z0-9_-]{40,128}\Z")
_HOST_LABEL = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")


class DirectTransferClientError(ValueError):
    """Safe error without a destination URL, token, or remote response body."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if not address.is_global or address.is_multicast:
        return False
    if isinstance(address, ipaddress.IPv6Address):
        return (address in ipaddress.ip_network("2000::/3")
                and address.ipv4_mapped is None
                and address.sixtofour is None and address.teredo is None)
    return True


def _host_list(value: str | set[str] | tuple[str, ...] | None, env_name: str) -> set[str]:
    if value is None:
        value = os.environ.get(env_name, "")
    items = value.split(",") if isinstance(value, str) else value
    return {str(item).strip().rstrip(".").lower() for item in items if str(item).strip()}


def _host_matches(host: str, policy: set[str]) -> bool:
    return any(host == item or (item.startswith("*.") and host.endswith(item[1:])
               and host != item[2:]) for item in policy)


def _normalize_invitation_url(url: str, allowed: set[str], denied: set[str]) -> tuple[str, int, str]:
    if not isinstance(url, str) or len(url) > 2048 or re.search(r"[\x00-\x20\x7f\\]", url):
        raise DirectTransferClientError("invalid_url", "Invitation URL is invalid.")
    try:
        parsed = urlsplit(url)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.query or parsed.fragment
                or not INVITATION_PATH.fullmatch(parsed.path)):
            raise ValueError("invalid transfer URL")
        port = parsed.port or 443
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        address = ipaddress.ip_address(host)
        host = address.compressed
    except ValueError:
        # An ordinary DNS hostname is checked separately from an IP literal.
        try:
            parsed = urlsplit(url)
            if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                    or parsed.password is not None or parsed.query or parsed.fragment
                    or not INVITATION_PATH.fullmatch(parsed.path)):
                raise ValueError("invalid transfer URL")
            port = parsed.port or 443
            host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except (ValueError, UnicodeError) as exc:
            raise DirectTransferClientError("invalid_url", "Invitation URL is invalid.") from exc
    except UnicodeError as exc:
        raise DirectTransferClientError("invalid_url", "Invitation URL is invalid.") from exc
    if (not 1 <= port <= 65535 or not host or len(host) > 253
            or "%" in host or host == "localhost"
            or host.endswith((".localhost", ".local", ".internal", ".test", ".invalid"))):
        raise DirectTransferClientError("blocked_host", "Invitation host is not allowed.")
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        if not all(_HOST_LABEL.fullmatch(label) for label in host.split(".")):
            raise DirectTransferClientError("blocked_host", "Invitation host is not allowed.") from None
    else:
        if not _public_address(str(literal)):
            raise DirectTransferClientError("blocked_host", "Invitation host is not allowed.")
    if _host_matches(host, denied) or (allowed and not _host_matches(host, allowed)):
        raise DirectTransferClientError("blocked_host", "Invitation host is not allowed.")
    return host, port, parsed.path


class DirectTransferClient:
    def __init__(self, *, allowed_hosts: str | set[str] | None = None,
                 denied_hosts: str | set[str] | None = None,
                 resolver=None, ssl_context: ssl.SSLContext | None = None):
        self.allowed_hosts = _host_list(allowed_hosts, "CTF_DIRECT_TRANSFER_ALLOW_HOSTS")
        self.denied_hosts = _host_list(denied_hosts, "CTF_DIRECT_TRANSFER_DENY_HOSTS")
        self.resolver = resolver or socket.getaddrinfo
        self.ssl_context = ssl_context or ssl.create_default_context()

    def validate_invitation(self, invitation_url: str, token: str) -> tuple[str, int, str]:
        """Reject malformed or blocked targets before exporting source data."""
        if not isinstance(token, str) or not _TOKEN.fullmatch(token):
            raise DirectTransferClientError("invalid_token", "Invitation token is invalid.")
        return _normalize_invitation_url(
            invitation_url, self.allowed_hosts, self.denied_hosts,
        )

    def _address(self, host: str, port: int) -> str:
        try:
            records = self.resolver(host, port, type=socket.SOCK_STREAM)
            addresses = list(dict.fromkeys(record[4][0] for record in records))
        except (OSError, UnicodeError) as exc:
            raise DirectTransferClientError("dns_failed", "Invitation host could not be resolved.") from exc
        if not addresses or not all(_public_address(address) for address in addresses):
            raise DirectTransferClientError("blocked_address", "Invitation host resolves to a blocked address.")
        return addresses[0]

    def _request(self, host: str, port: int, path: str, token: str,
                 method: str, suffix: str, body: bytes,
                 *, chunk_digest: str | None = None) -> dict:
        # Resolve immediately before each new connection, then pin the socket
        # to that validated address while retaining host for SNI and TLS checks.
        address = self._address(host, port)
        connection = http.client.HTTPSConnection(
            host, port, timeout=REQUEST_TIMEOUT_SECONDS, context=self.ssl_context,
        )

        def pinned_connect(_destination, timeout=REQUEST_TIMEOUT_SECONDS, source_address=None):
            return socket.create_connection((address, port), timeout, source_address)

        connection._create_connection = pinned_connect
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
            "Content-Type": "application/octet-stream" if chunk_digest else "application/json",
            "Content-Length": str(len(body)),
            "Connection": "close",
            "User-Agent": "CTF-Agent-Direct-Transfer/1",
        }
        if chunk_digest:
            headers["X-Chunk-SHA256"] = chunk_digest

        def expire():
            active = connection.sock
            if active is not None:
                try:
                    active.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

        watchdog = threading.Timer(REQUEST_TIMEOUT_SECONDS + 5, expire)
        watchdog.daemon = True
        watchdog.start()
        try:
            connection.request(method, path + suffix, body=body, headers=headers)
            response = connection.getresponse()
            content = response.read(MAX_RESPONSE_BYTES + 1)
            if len(content) > MAX_RESPONSE_BYTES:
                raise DirectTransferClientError("response_too_large", "Receiver response is too large.")
            if not 200 <= response.status < 300:
                # Never surface response bodies. Even redirect Location could
                # carry a token, and redirects are never followed.
                raise DirectTransferClientError("receiver_rejected", f"Receiver rejected transfer ({response.status}).")
            try:
                decoded = json.loads(content)
            except (UnicodeError, ValueError) as exc:
                raise DirectTransferClientError("invalid_response", "Receiver response is invalid.") from exc
            if not isinstance(decoded, dict):
                raise DirectTransferClientError("invalid_response", "Receiver response is invalid.")
            return decoded
        except DirectTransferClientError:
            raise
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            raise DirectTransferClientError("network_error", "Secure connection to receiver failed.") from exc
        finally:
            watchdog.cancel()
            connection.close()

    def send_bundle(self, invitation_url: str, token: str, archive: Path,
                    *, scope: str) -> dict:
        if scope not in {"workspace", "challenge"}:
            raise DirectTransferClientError("invalid_scope", "Transfer scope is invalid.")
        host, port, path = self.validate_invitation(invitation_url, token)
        archive = Path(archive)
        try:
            details = archive.lstat()
            if not stat.S_ISREG(details.st_mode) or not 0 < details.st_size <= MAX_BUNDLE_BYTES:
                raise DirectTransferClientError("invalid_bundle", "Bundle size is not allowed.")
            digest = hashlib.sha256()
            with archive.open("rb") as source:
                while chunk := source.read(CHUNK_BYTES):
                    digest.update(chunk)
            if archive.stat().st_size != details.st_size:
                raise DirectTransferClientError("changed_bundle", "Bundle changed during transfer.")
        except OSError as exc:
            raise DirectTransferClientError("invalid_bundle", "Bundle could not be read.") from exc
        payload = json.dumps({"scope": scope, "size": details.st_size,
                              "sha256": digest.hexdigest()}, separators=(",", ":")).encode()
        started = time.monotonic()
        prepared = self._request(host, port, path, token, "POST", "/prepare", payload)
        if prepared.get("status") == "completed":
            return self._request(host, port, path, token, "POST", "/complete", b"{}")
        offset = prepared.get("offset")
        if type(offset) is not int or not 0 <= offset <= details.st_size:
            raise DirectTransferClientError("invalid_response", "Receiver upload offset is invalid.")
        with archive.open("rb") as source:
            source.seek(offset)
            while offset < details.st_size:
                if time.monotonic() - started > TRANSFER_DEADLINE_SECONDS:
                    raise DirectTransferClientError("deadline", "Direct transfer time limit was reached.")
                chunk = source.read(min(CHUNK_BYTES, details.st_size - offset))
                if not chunk:
                    raise DirectTransferClientError("changed_bundle", "Bundle changed during transfer.")
                reply = self._request(
                    host, port, path, token, "PUT", f"/chunks?offset={offset}",
                    chunk, chunk_digest=hashlib.sha256(chunk).hexdigest(),
                )
                next_offset = reply.get("offset")
                if type(next_offset) is not int or next_offset < offset + len(chunk) or next_offset > details.st_size:
                    raise DirectTransferClientError("invalid_response", "Receiver upload offset is invalid.")
                offset = next_offset
                source.seek(offset)
        if archive.stat().st_size != details.st_size:
            raise DirectTransferClientError("changed_bundle", "Bundle changed during transfer.")
        return self._request(host, port, path, token, "POST", "/complete", b"{}")
