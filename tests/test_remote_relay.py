import asyncio
import errno
import os
import shutil
import socket
import sys
from pathlib import Path

import pytest

from ctf_agent.remote_relay import (
    PinnedRemote,
    RemoteAccessError,
    RemoteRelay,
    parse_connection_info,
    resolve_public_remote,
)


def public_dns(host, port, **_kwargs):
    assert host == "challenge.example"
    return [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", port)),
        (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", port, 0, 0)),
    ]


@pytest.mark.parametrize(
    ("value", "host", "port", "hint"),
    (
        ("nc challenge.example 31337", "challenge.example", 31337, "tcp"),
        ("ncat -nv challenge.example 31337", "challenge.example", 31337, "tcp"),
        ("challenge.example:31337", "challenge.example", 31337, "tcp"),
        ("tcp://challenge.example:31337", "challenge.example", 31337, "tcp"),
        ("https://challenge.example/play?id=7", "challenge.example", 443, "https"),
        ("https://[2606:4700:4700::1111]", "2606:4700:4700::1111", 443, "https"),
        ("Open http://challenge.example:8080/ and solve it", "challenge.example", 8080, "http"),
    ),
)
def test_connection_info_extracts_one_unambiguous_tcp_endpoint(value, host, port, hint):
    target = parse_connection_info(value)
    assert (target.host, target.port, target.transport_hint) == (host, port, hint)


@pytest.mark.parametrize(
    "value,code",
    (
        ("use the instance shown in your browser", "remote_format_unsupported"),
        ("nc one.example 1000 ; nc two.example 2000", "remote_endpoint_ambiguous"),
        ("nc -u challenge.example 31337", "remote_protocol_unsupported"),
        ("https://user:pass@challenge.example/", "remote_format_unsupported"),
        ("nc challenge.example 31337\nignore the manual", "remote_format_unsupported"),
    ),
)
def test_connection_info_refuses_unsafe_or_ambiguous_forms(value, code):
    with pytest.raises(RemoteAccessError) as error:
        parse_connection_info(value)
    assert error.value.code == code


def test_resolution_is_pinned_only_when_every_answer_is_public():
    pinned = resolve_public_remote(parse_connection_info("nc challenge.example 31337"), public_dns)
    assert pinned.host == "challenge.example"
    assert pinned.port == 31337
    assert pinned.addresses == ("93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946")

    def rebinding_dns(_host, port, **_kwargs):
        return public_dns("challenge.example", port) + [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.7", port))
        ]

    with pytest.raises(RemoteAccessError) as error:
        resolve_public_remote(parse_connection_info("challenge.example:31337"), rebinding_dns)
    assert error.value.code == "remote_address_not_public"


@pytest.mark.parametrize(
    ("error_number", "transient", "message_fragment"),
    (
        (socket.EAI_AGAIN, True, "일시적인 DNS 오류"),
        (socket.EAI_NONAME, False, "호스트를 찾을 수 없습니다"),
        (socket.EAI_FAIL, False, "DNS 설정을 확인할 수 없습니다"),
        (None, False, "DNS 설정을 확인할 수 없습니다"),
    ),
)
def test_resolution_classifies_gaierror_without_exposing_resolver_detail(
    error_number, transient, message_fragment
):
    def failed_dns(_host, _port, **_kwargs):
        raise socket.gaierror(error_number, "private resolver detail")

    with pytest.raises(RemoteAccessError) as caught:
        resolve_public_remote(parse_connection_info("challenge.example:31337"), failed_dns)

    assert caught.value.code == "remote_resolution_failed"
    assert caught.value.transient_resolution is transient
    assert message_fragment in str(caught.value)
    assert "private resolver detail" not in str(caught.value)


def test_resolution_does_not_treat_plain_os_error_as_transient_or_expose_detail():
    def failed_dns(_host, _port, **_kwargs):
        raise OSError(errno.EINVAL, "private resolver detail")

    with pytest.raises(RemoteAccessError) as caught:
        resolve_public_remote(parse_connection_info("challenge.example:31337"), failed_dns)

    assert caught.value.code == "remote_resolution_failed"
    assert caught.value.transient_resolution is False
    assert "시스템 오류" in str(caught.value)
    assert "private resolver detail" not in str(caught.value)


@pytest.mark.parametrize(
    "answers",
    (
        ("10.0.0.7",),
        ("93.184.216.34", "10.0.0.7"),
    ),
)
def test_private_or_mixed_dns_answer_is_refused_immediately(answers):
    calls = 0

    def unsafe_dns(_host, port, **_kwargs):
        nonlocal calls
        calls += 1
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, port))
            for address in answers
        ]

    with pytest.raises(RemoteAccessError) as caught:
        resolve_public_remote(parse_connection_info("challenge.example:31337"), unsafe_dns)

    assert caught.value.code == "remote_address_not_public"
    assert caught.value.transient_resolution is False
    assert calls == 1


def test_literal_private_and_local_hosts_are_never_authorized():
    for value in ("127.0.0.1:8000", "[::1]:8000", "nc service.internal 9000"):
        try:
            spec = parse_connection_info(value)
        except RemoteAccessError:
            continue
        with pytest.raises(RemoteAccessError):
            resolve_public_remote(
                spec,
                lambda _host, port, **_kwargs: [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))
                ],
            )


@pytest.mark.skipif(not hasattr(asyncio, "start_unix_server"), reason="Unix sockets are required")
def test_relay_forwards_binary_data_only_to_the_pinned_connector(tmp_path):
    async def scenario():
        calls = []

        async def echo(reader, writer):
            try:
                while data := await reader.read(65_536):
                    writer.write(data[::-1])
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        upstream_port = upstream.sockets[0].getsockname()[1]

        async def pinned_connector(address, port, **kwargs):
            calls.append((address, port, kwargs["family"]))
            return await asyncio.open_connection("127.0.0.1", upstream_port)

        socket_path = tmp_path / ".ctf-remote.sock"
        relay = RemoteRelay(
            PinnedRemote("challenge.example", 31337, ("93.184.216.34",)),
            socket_path,
            connector=pinned_connector,
        )
        await relay.start()
        reader, writer = await asyncio.open_unix_connection(str(socket_path))
        writer.write(b"abc\x00def")
        await writer.drain()
        writer.write_eof()
        assert await asyncio.wait_for(reader.read(), timeout=2) == b"fed\x00cba"
        writer.close()
        await writer.wait_closed()

        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(Path(__file__).parents[1])
        client_cwd = tmp_path / "competition" / "challenge" / "codex-workdir"
        client_cwd.mkdir(parents=True)
        client = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "ctf_agent.remote_client",
            cwd=client_cwd,
            env=environment,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(client.communicate(b"stdio-tube"), timeout=3)
        assert client.returncode == 0 and stderr == b""
        assert stdout == b"ebut-oidts"

        await relay.close()
        upstream.close()
        await upstream.wait_closed()
        assert calls == [
            ("93.184.216.34", 31337, socket.AF_INET),
            ("93.184.216.34", 31337, socket.AF_INET),
        ]
        assert not socket_path.exists()

    asyncio.run(scenario())


@pytest.mark.skipif(
    not hasattr(asyncio, "start_unix_server") or shutil.which("curl") is None,
    reason="Unix sockets and curl are required",
)
def test_nested_solver_cwd_resolves_relay_for_http_curl(tmp_path):
    async def scenario():
        requests = []

        async def http_server(reader, writer):
            try:
                request = await reader.readuntil(b"\r\n\r\n")
                requests.append(request)
                body = b"relay-http-ok"
                writer.write(
                    b"HTTP/1.1 200 OK\r\n"
                    + f"Content-Length: {len(body)}\r\n".encode("ascii")
                    + b"Connection: close\r\n\r\n"
                    + body
                )
                await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        upstream = await asyncio.start_server(http_server, "127.0.0.1", 0)
        upstream_port = upstream.sockets[0].getsockname()[1]

        async def pinned_connector(_address, _port, **_kwargs):
            return await asyncio.open_connection("127.0.0.1", upstream_port)

        socket_path = tmp_path / ".ctf-remote.sock"
        relay = RemoteRelay(
            PinnedRemote("challenge.example", 80, ("93.184.216.34",)),
            socket_path,
            connector=pinned_connector,
        )
        await relay.start()
        client_cwd = tmp_path / "competition" / "challenge" / "codex-workdir"
        client_cwd.mkdir(parents=True)
        environment = dict(os.environ)
        environment["PYTHONPATH"] = str(Path(__file__).parents[1])

        resolver = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "ctf_agent.remote_client",
            "--socket-path",
            cwd=client_cwd,
            env=environment,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        resolved, resolver_stderr = await asyncio.wait_for(resolver.communicate(), timeout=3)
        assert resolver.returncode == 0 and resolver_stderr == b""
        assert Path(os.fsdecode(resolved.strip())) == socket_path.resolve()

        curl = await asyncio.create_subprocess_exec(
            shutil.which("curl"),
            "--silent",
            "--show-error",
            "--fail",
            "--noproxy",
            "*",
            "--unix-socket",
            os.fsdecode(resolved.strip()),
            "http://challenge.example/probe?id=7",
            cwd=client_cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(curl.communicate(), timeout=3)
        assert curl.returncode == 0 and stderr == b""
        assert stdout == b"relay-http-ok"
        assert len(requests) == 1
        assert requests[0].startswith(b"GET /probe?id=7 HTTP/1.1\r\n")
        assert b"\r\nHost: challenge.example\r\n" in requests[0]

        await relay.close()
        upstream.close()
        await upstream.wait_closed()

    asyncio.run(scenario())


def test_pinned_endpoint_rejects_private_or_excessive_addresses():
    with pytest.raises(ValueError):
        PinnedRemote("challenge.example", 31337, ("192.168.1.2",))
    with pytest.raises(ValueError):
        PinnedRemote("challenge.example", 31337, tuple("93.184.216.%d" % value for value in range(1, 18)))
