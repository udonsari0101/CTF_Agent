"""Job-scoped access to one explicitly authorized public CTF endpoint.

Model commands never receive an Internet socket.  The trusted worker resolves
and pins one endpoint from CTFd ``connection_info``, then relays a Unix stream
socket to only those checked IP addresses and the checked port.
"""

from __future__ import annotations

import asyncio
import ipaddress
import os
import re
import shlex
import socket
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit


MAX_CONNECTION_INFO_CHARS = 2_000
MAX_RESOLVED_ADDRESSES = 16
MAX_CONCURRENT_CONNECTIONS = 8
MAX_CONNECTIONS_PER_JOB = 128
CONNECT_TIMEOUT_SECONDS = 12.0
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_TRANSIENT_GAIERROR_CODES = frozenset(
    value
    for value in (getattr(socket, "EAI_AGAIN", None),)
    if isinstance(value, int)
)
_MISSING_HOST_GAIERROR_CODES = frozenset(
    value
    for value in (
        getattr(socket, "EAI_NONAME", None),
        getattr(socket, "EAI_NODATA", None),
    )
    if isinstance(value, int)
)
_HOST_PORT = re.compile(
    r"(?<![A-Za-z0-9_.-])"
    r"(?P<host>\[[0-9A-Fa-f:.]+\]|(?:[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?)|(?:\d{1,3}\.){3}\d{1,3})"
    r":(?P<port>\d{1,5})(?!\d)"
)
_URL = re.compile(r"(?i)\b(?:https?|tcp)://[^\s;]+")


class RemoteAccessError(ValueError):
    """A bounded error safe to map to a public solver refusal."""

    def __init__(self, code: str, message: str, *, transient_resolution: bool = False):
        super().__init__(message)
        self.code = code
        self.transient_resolution = transient_resolution


@dataclass(frozen=True, slots=True)
class RemoteSpec:
    host: str
    port: int
    transport_hint: str = "tcp"


@dataclass(frozen=True, slots=True)
class PinnedRemote:
    host: str
    port: int
    addresses: tuple[str, ...]
    transport_hint: str = "tcp"

    def __post_init__(self) -> None:
        normalized = _normalize_host(self.host)
        if not isinstance(self.port, int) or isinstance(self.port, bool) or not 1 <= self.port <= 65_535:
            raise ValueError("invalid remote port")
        if not self.addresses or len(self.addresses) > MAX_RESOLVED_ADDRESSES:
            raise ValueError("invalid pinned address count")
        addresses = tuple(dict.fromkeys(str(ipaddress.ip_address(item)) for item in self.addresses))
        if not addresses or not all(_public_address(item) for item in addresses):
            raise ValueError("pinned endpoint contains a non-public address")
        if self.transport_hint not in {"tcp", "http", "https"}:
            raise ValueError("invalid transport hint")
        object.__setattr__(self, "host", normalized)
        object.__setattr__(self, "addresses", addresses)


def _normalize_host(value: str) -> str:
    if not isinstance(value, str):
        raise RemoteAccessError("remote_format_unsupported", "원격 호스트 형식을 지원하지 않습니다.")
    host = value.strip().strip("[]").rstrip(".")
    try:
        normalized = str(ipaddress.ip_address(host))
    except ValueError:
        try:
            normalized = host.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise RemoteAccessError("remote_format_unsupported", "원격 호스트 형식을 지원하지 않습니다.") from exc
        if (
            not normalized
            or len(normalized) > 253
            or normalized == "localhost"
            or normalized.endswith((".localhost", ".local", ".internal"))
            or not re.fullmatch(
                r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
                r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?",
                normalized,
            )
        ):
            raise RemoteAccessError("remote_format_unsupported", "원격 호스트 형식을 지원하지 않습니다.")
    return normalized


def _port(value: object) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise RemoteAccessError("remote_format_unsupported", "원격 포트 형식을 지원하지 않습니다.") from exc
    if isinstance(value, bool) or not 1 <= result <= 65_535:
        raise RemoteAccessError("remote_format_unsupported", "원격 포트 형식을 지원하지 않습니다.")
    return result


def _public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if not address.is_global or address.is_multicast:
        return False
    if isinstance(address, ipaddress.IPv6Address):
        return (
            address in ipaddress.ip_network("2000::/3")
            and address.sixtofour is None
            and address.teredo is None
        )
    return True


def _candidate(host: str, port: object, hint: str) -> RemoteSpec:
    return RemoteSpec(_normalize_host(host), _port(port), hint)


def parse_connection_info(value: str) -> RemoteSpec:
    """Extract exactly one TCP endpoint without evaluating remote text.

    Supported forms cover the standard CTFd values: HTTP(S)/TCP URLs,
    ``nc HOST PORT`` (including harmless nc flags), and ``HOST:PORT``.  Extra
    prose is allowed, but zero or multiple distinct destinations are refused.
    """

    if (
        not isinstance(value, str)
        or not value.strip()
        or len(value) > MAX_CONNECTION_INFO_CHARS
        or "`" in value
        or "\r" in value
        or "\n" in value
        or _CONTROL.search(value)
    ):
        raise RemoteAccessError("remote_format_unsupported", "원격 접속 정보 형식을 지원하지 않습니다.")

    candidates: dict[tuple[str, int], RemoteSpec] = {}

    def add(spec: RemoteSpec) -> None:
        key = (spec.host, spec.port)
        previous = candidates.get(key)
        # A URL is a better client hint than a duplicate bare host:port match.
        if previous is None or (previous.transport_hint == "tcp" and spec.transport_hint != "tcp"):
            candidates[key] = spec

    url_spans: list[tuple[int, int]] = []
    for match in _URL.finditer(value):
        url_spans.append(match.span())
        token = match.group(0).rstrip(".,)}")
        # A closing bracket is part of a bracketed IPv6 URL authority when no
        # explicit port follows it.  Strip it only when it is prose punctuation
        # around an otherwise ordinary URL (for example ``[https://host]``).
        if token.endswith("]"):
            authority = token.split("://", 1)[1].split("/", 1)[0]
            if not (authority.startswith("[") and authority.endswith("]")):
                token = token[:-1]
        try:
            parsed = urlsplit(token)
            if parsed.username is not None or parsed.password is not None or not parsed.hostname:
                raise ValueError
            if parsed.scheme.lower() == "https":
                port, hint = parsed.port or 443, "https"
            elif parsed.scheme.lower() == "http":
                port, hint = parsed.port or 80, "http"
            elif parsed.scheme.lower() == "tcp" and parsed.port is not None:
                port, hint = parsed.port, "tcp"
            else:
                raise ValueError
            add(_candidate(parsed.hostname, port, hint))
        except (ValueError, UnicodeError):
            raise RemoteAccessError("remote_format_unsupported", "원격 URL 형식을 지원하지 않습니다.") from None

    for segment in value.split(";"):
        try:
            tokens = shlex.split(segment, posix=True)
        except ValueError:
            raise RemoteAccessError("remote_format_unsupported", "원격 접속 정보 형식을 지원하지 않습니다.") from None
        command_index = next(
            (index for index, token in enumerate(tokens) if os.path.basename(token).lower() in {"nc", "ncat", "netcat"}),
            None,
        )
        if command_index is None:
            continue
        arguments = tokens[command_index + 1 :]
        if any(token == "-u" or (token.startswith("-") and "u" in token[1:]) for token in arguments[:-2]):
            raise RemoteAccessError("remote_protocol_unsupported", "현재 원격 릴레이는 TCP 문제만 지원합니다.")
        positional = [token for token in arguments if not token.startswith("-")]
        if len(positional) < 2:
            raise RemoteAccessError("remote_format_unsupported", "nc 원격 주소에서 호스트와 포트를 찾지 못했습니다.")
        add(_candidate(positional[-2], positional[-1], "tcp"))

    for match in _HOST_PORT.finditer(value):
        if any(match.start() < end and match.end() > start for start, end in url_spans):
            continue
        add(_candidate(match.group("host"), match.group("port"), "tcp"))

    if not candidates:
        raise RemoteAccessError(
            "remote_format_unsupported",
            "원격 접속 정보에서 지원되는 TCP/HTTP(S) 주소 하나를 찾지 못했습니다.",
        )
    if len(candidates) != 1:
        raise RemoteAccessError(
            "remote_endpoint_ambiguous",
            "원격 접속 정보에 서로 다른 대상이 여러 개 있어 자동 풀이를 시작할 수 없습니다.",
        )
    return next(iter(candidates.values()))


def resolve_public_remote(
    spec: RemoteSpec,
    resolver: Callable = socket.getaddrinfo,
) -> PinnedRemote:
    """Resolve once, classify transient failure, and pin only public answers."""

    try:
        records = resolver(spec.host, spec.port, type=socket.SOCK_STREAM)
        addresses = tuple(dict.fromkeys(record[4][0] for record in records))
    except socket.gaierror as exc:
        if exc.errno in _TRANSIENT_GAIERROR_CODES:
            message = (
                "원격 문제 호스트를 확인하지 못했습니다. 일시적인 DNS 오류일 수 있으니 "
                "잠시 후 다시 시도해 주세요."
            )
            transient = True
        elif exc.errno in _MISSING_HOST_GAIERROR_CODES:
            message = (
                "원격 문제 호스트를 찾을 수 없습니다. CTFd에서 문제 인스턴스를 "
                "새로고침하거나 원격 주소를 확인해 주세요."
            )
            transient = False
        else:
            message = (
                "원격 문제 호스트의 DNS 설정을 확인할 수 없습니다. "
                "원격 주소와 DNS 설정을 확인해 주세요."
            )
            transient = False
        raise RemoteAccessError(
            "remote_resolution_failed",
            message,
            transient_resolution=transient,
        ) from exc
    except OSError as exc:
        raise RemoteAccessError(
            "remote_resolution_failed",
            "원격 문제 호스트의 DNS 확인 중 시스템 오류가 발생했습니다. 서버 네트워크와 DNS 설정을 확인해 주세요.",
        ) from exc
    except UnicodeError as exc:
        raise RemoteAccessError(
            "remote_resolution_failed",
            "원격 문제 호스트를 확인하지 못했습니다. 원격 주소를 확인한 뒤 다시 시도해 주세요.",
        ) from exc
    if not addresses:
        raise RemoteAccessError(
            "remote_resolution_failed",
            "원격 문제 호스트의 주소 응답이 비어 있습니다. 잠시 후 다시 시도해 주세요.",
            transient_resolution=True,
        )
    if len(addresses) > MAX_RESOLVED_ADDRESSES:
        raise RemoteAccessError("remote_resolution_failed", "원격 문제 호스트의 주소 응답을 확인할 수 없습니다.")
    if not all(_public_address(address) for address in addresses):
        raise RemoteAccessError(
            "remote_address_not_public",
            "다중 사용자 solver에서는 공인 인터넷 주소의 원격 문제만 연결할 수 있습니다.",
        )
    return PinnedRemote(spec.host, spec.port, addresses, spec.transport_hint)


class RemoteRelay:
    """Bounded Unix-socket relay to one pinned remote endpoint."""

    def __init__(
        self,
        endpoint: PinnedRemote,
        socket_path: Path,
        *,
        connector: Callable[..., object] = asyncio.open_connection,
        max_concurrent: int = MAX_CONCURRENT_CONNECTIONS,
        max_connections: int = MAX_CONNECTIONS_PER_JOB,
    ):
        self.endpoint = endpoint
        self.socket_path = Path(socket_path)
        self.connector = connector
        self.max_concurrent = max_concurrent
        self.max_connections = max_connections
        self.server: asyncio.AbstractServer | None = None
        self.handlers: set[asyncio.Task] = set()
        self.connections = 0
        self.closed = False

    async def start(self) -> None:
        if os.name != "posix" or not hasattr(asyncio, "start_unix_server"):
            raise RemoteAccessError("remote_relay_unavailable", "이 worker에서는 Unix 원격 릴레이를 사용할 수 없습니다.")
        parent = self.socket_path.parent
        if parent.is_symlink() or not parent.is_dir() or self.socket_path.exists() or self.socket_path.is_symlink():
            raise RemoteAccessError("remote_relay_unavailable", "원격 릴레이 소켓 경로를 안전하게 준비할 수 없습니다.")
        self.server = await asyncio.start_unix_server(self._handle, path=str(self.socket_path), limit=65_536)
        self.socket_path.chmod(0o600)
        info = self.socket_path.lstat()
        if not stat.S_ISSOCK(info.st_mode) or info.st_nlink != 1:
            await self.close()
            raise RemoteAccessError("remote_relay_unavailable", "원격 릴레이 소켓을 확인할 수 없습니다.")

    async def _connect(self):
        last_error: BaseException | None = None
        for address in self.endpoint.addresses:
            family = socket.AF_INET6 if ipaddress.ip_address(address).version == 6 else socket.AF_INET
            try:
                return await asyncio.wait_for(
                    self.connector(address, self.endpoint.port, family=family, limit=65_536),
                    timeout=CONNECT_TIMEOUT_SECONDS,
                )
            except (OSError, asyncio.TimeoutError) as exc:
                last_error = exc
        raise OSError("authorized remote endpoint is unavailable") from last_error

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self.handlers.add(task)
        remote_writer: asyncio.StreamWriter | None = None
        try:
            if self.closed or len(self.handlers) > self.max_concurrent or self.connections >= self.max_connections:
                return
            self.connections += 1
            remote_reader, remote_writer = await self._connect()

            async def pump(source: asyncio.StreamReader, destination: asyncio.StreamWriter) -> None:
                while data := await source.read(65_536):
                    destination.write(data)
                    await destination.drain()
                try:
                    destination.write_eof()
                except (AttributeError, OSError, RuntimeError):
                    pass

            upstream = asyncio.create_task(pump(reader, remote_writer))
            downstream = asyncio.create_task(pump(remote_reader, writer))
            done, _pending = await asyncio.wait((upstream, downstream), return_when=asyncio.FIRST_COMPLETED)
            if downstream in done:
                upstream.cancel()
                await asyncio.gather(upstream, return_exceptions=True)
            else:
                await downstream
        except (OSError, asyncio.TimeoutError, asyncio.CancelledError):
            pass
        finally:
            if remote_writer is not None:
                remote_writer.close()
                try:
                    await remote_writer.wait_closed()
                except (OSError, RuntimeError):
                    pass
            writer.close()
            try:
                await writer.wait_closed()
            except (OSError, RuntimeError):
                pass
            if task is not None:
                self.handlers.discard(task)

    async def close(self) -> None:
        self.closed = True
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None
        current = asyncio.current_task()
        pending = [task for task in self.handlers if task is not current and not task.done()]
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)
        self.handlers.clear()
        try:
            if self.socket_path.is_socket() and not self.socket_path.is_symlink():
                self.socket_path.unlink()
        except OSError:
            pass


__all__ = [
    "PinnedRemote",
    "RemoteAccessError",
    "RemoteRelay",
    "RemoteSpec",
    "parse_connection_info",
    "resolve_public_remote",
]
