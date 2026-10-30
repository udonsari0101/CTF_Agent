"""Bounded CTFd challenge import and explicit flag-submission HTTP client.

API references: https://docs.ctfd.io/docs/api/getting-started/ and
https://github.com/CTFd/CTFd/blob/master/CTFd/api/v1/challenges.py
Imports read the challenge list, challenge details, and attachment URLs. The
submission method is called only by the separate opt-in durable submission
service. Remote templates/scripts are never evaluated; archives are never
unpacked.
"""

from __future__ import annotations

import hashlib
import http.client
import http.cookiejar
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import sqlite3
import ssl
import stat
import threading
import time
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass
from datetime import datetime, timezone
from email.message import Message
from html.parser import HTMLParser
from pathlib import Path
from typing import Callable, Literal
from urllib.parse import quote, unquote, urlencode, urljoin, urlsplit, urlunsplit
from urllib.request import Request as CookieRequest
from uuid import uuid4

from .storage_budget import MAX_SQLITE_INTEGER, StorageBudgetError, get_storage_budget
from .process_lock import ProcessFileLock


class CTFdError(ValueError):
    """Safe error text suitable for the management API (never response bodies)."""

    def __init__(self, message: str, *, received_bytes: int = 0):
        super().__init__(message)
        self.received_bytes = received_bytes


_REMOTE_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
MAX_CONNECTION_INFO_CHARS = 2000


def insecure_http_credentials_allowed() -> bool:
    """Return whether the operator explicitly allowed plaintext CTFd auth."""

    return os.environ.get("CTF_CTFD_ALLOW_INSECURE_HTTP", "").strip().lower() in {
        "1", "true", "yes", "on",
    }


def connection_info(value) -> str:
    """Return bounded CTFd connection text suitable for storage and a brief.

    CTFd's standard ``connection_info`` field is Text. Custom challenge types
    can return arbitrary JSON, so non-text values are ignored rather than
    turning a plugin-controlled object into Python repr text.
    """

    if not isinstance(value, str):
        return ""
    value = value.replace("\r\n", "\n").replace("\r", "\n").strip()
    if _REMOTE_CONTROL.search(value):
        return ""
    # This value is later embedded inside an inline-code field in the trusted
    # solver manual.  Keep multiple endpoints usable while preventing a CTFd
    # plugin from closing that field or adding new Markdown instructions.
    lines = [" ".join(line.split()) for line in value.split("\n")]
    value = " ; ".join(line for line in lines if line).replace("`", "'")
    return value[:MAX_CONNECTION_INFO_CHARS].rstrip()


@dataclass(frozen=True)
class Limits:
    challenges: int = 100
    files_per_challenge: int = 20
    files: int = 200
    file_bytes: int | None = None
    total_bytes: int | None = None
    json_bytes: int = 2 * 1024 * 1024
    redirects: int = 4
    timeout: float = 10.0
    duration: float | None = None


@dataclass(frozen=True)
class Target:
    url: str
    scheme: str
    host: str
    port: int
    address: str


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    content: bytes
    cookies: tuple[str, ...] = ()
    received_bytes: int = 0


def normalize_url(url: str, *, site: bool = False) -> str:
    if not isinstance(url, str) or len(url) > 4096:
        raise CTFdError("URL must be a string of at most 4096 characters.")
    url = url.strip()
    if site and "://" not in url:
        url = "https:" + url if url.startswith("//") else "https://" + url
    if re.search(r"[\x00-\x20\x7f\\]", url):
        raise CTFdError("URL contains invalid characters.")
    try:
        parsed = urlsplit(url)
        if parsed.scheme not in {"https", "http"} or not parsed.hostname:
            raise CTFdError("Use a complete HTTP or HTTPS site URL.")
        if parsed.username is not None or parsed.password is not None:
            raise CTFdError("Credentials must not be included in a URL.")
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        port = parsed.port if parsed.port is not None else (443 if parsed.scheme == "https" else 80)
    except (ValueError, UnicodeError) as exc:
        raise CTFdError("Invalid URL.") from exc
    if "%" in host or not 1 <= port <= 65535:
        raise CTFdError("Invalid host or port.")
    if host == "localhost" or host.endswith((".localhost", ".local", ".internal")):
        raise CTFdError("Only public internet hosts may be imported.")
    authority = f"[{host}]" if ":" in host else host
    if port != (443 if parsed.scheme == "https" else 80):
        authority += f":{port}"
    path = parsed.path.rstrip("/") if site else parsed.path
    if site and (parsed.query or parsed.fragment):
        raise CTFdError("Enter the CTFd base URL without a query or fragment.")
    try:
        # Keep reserved escapes (notably %2F) distinct while canonicalizing raw
        # Unicode and hex casing to the same URL and source deduplication key.
        path = quote(path, safe="/%:@!$&'()*+,;=-._~")
        query = quote(parsed.query, safe="/%?:@!$&'()*+,;=-._~") if not site else ""
    except UnicodeError as exc:
        raise CTFdError("Invalid URL encoding.") from exc
    if site:
        path = re.sub(r"%[0-9a-fA-F]{2}", lambda match: match.group().upper(), path)
    # Preserve existing attachment escapes and the query verbatim: a CDN may
    # have signed that exact representation, even when escapes are equivalent.
    normalized = urlunsplit((parsed.scheme, authority, path, query, ""))
    if len(normalized) > 4096:
        raise CTFdError("The encoded URL exceeds 4096 characters.")
    return normalized


def origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    return parsed.scheme, parsed.hostname or "", parsed.port or (443 if parsed.scheme == "https" else 80)


def _public_address(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    if not address.is_global or address.is_multicast:
        return False
    if isinstance(address, ipaddress.IPv6Address):
        # Exclude transition/translation ranges that can embed private IPv4.
        return (address in ipaddress.ip_network("2000::/3")
                and address.sixtofour is None and address.teredo is None)
    return True


def resolve_target(url: str, resolver: Callable = socket.getaddrinfo) -> Target:
    url = normalize_url(url)
    scheme, host, port = origin(url)
    try:
        records = resolver(host, port, type=socket.SOCK_STREAM)
        addresses = list(dict.fromkeys(record[4][0] for record in records))
    except (OSError, UnicodeError) as exc:
        raise CTFdError("The remote host could not be resolved.") from exc
    if not addresses or not all(_public_address(address) for address in addresses):
        raise CTFdError("Only public internet addresses may be imported.")
    return Target(url, scheme, host, port, addresses[0])


def public_get(target: Target, headers: dict[str, str], maximum: int | None, timeout: float,
               deadline: float, *, method: str = "GET", body: bytes | None = None,
               sink: Callable | None = None, on_headers: Callable | None = None,
               cancel: threading.Event | None = None) -> Response:
    """Connect to the validated IP, retaining the hostname for HTTPS verification."""
    if target.scheme == "https":
        connection = http.client.HTTPSConnection(target.host, target.port,
                                                  timeout=timeout, context=ssl.create_default_context())
    else:
        connection = http.client.HTTPConnection(target.host, target.port, timeout=timeout)

    def pinned_connect(_address, socket_timeout=timeout, source_address=None, **_kwargs):
        # No second hostname resolution is performed by the socket layer.
        return socket.create_connection((target.address, target.port), socket_timeout, source_address)

    connection._create_connection = pinned_connect
    expired = threading.Event()
    connected_socket = [None]

    def expire_request():
        expired.set()
        # Closing a socket alone can leave a buffered read blocked on some OSes.
        # Shutdown interrupts a server that trickles bytes to avoid socket timeouts.
        active_socket = connected_socket[0] or getattr(connection, "sock", None)
        if active_socket is not None:
            try:
                active_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    stopped = threading.Event()
    activity = [time.monotonic()]
    started = activity[0]

    def watch():
        while not stopped.wait(min(.1, max(.01, timeout / 4))):
            now = time.monotonic()
            if (cancel is not None and cancel.is_set()) or now >= deadline or now - (activity[0] if sink else started) >= timeout:
                expire_request()
                return

    timer = threading.Thread(target=watch, daemon=True)
    timer.start()
    content = bytearray()
    received = 0
    response = None
    try:
        parsed = urlsplit(target.url)
        path = urlunsplit(("", "", quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~"),
                          quote(parsed.query, safe="/%?:@!$&'()*+,;=-._~"), ""))
        if method == "GET" and body is None:
            connection.request("GET", path, headers=headers)
        elif method == "POST":
            connection.request("POST", path, body=body, headers=headers)
        else:
            raise CTFdError("Unsupported CTFd request method.")
        connected_socket[0] = getattr(connection, "sock", None)
        response = connection.getresponse()
        received_headers = {key.lower(): value for key, value in response.getheaders()}
        cookies = tuple(value for key, value in response.getheaders() if key.lower() == "set-cookie")
        if response.status in {301, 302, 303, 307, 308}:
            return Response(response.status, received_headers, b"", cookies)
        try:
            size = int(received_headers.get("content-length", "0"))
        except ValueError as exc:
            raise CTFdError("Remote content length is invalid.") from exc
        effective_maximum = maximum if 200 <= response.status < 300 else 2 * 1024 * 1024
        if size < 0 or (effective_maximum is not None and size > effective_maximum):
            raise CTFdError("The remote response exceeds the import size limit.")
        if received_headers.get("content-encoding", "identity").lower() not in {"", "identity"}:
            raise CTFdError("Compressed HTTP responses are not supported by this importer.")
        writing = sink is not None and 200 <= response.status < 300
        if writing and on_headers is not None:
            on_headers(response.status, received_headers)
        while True:
            if cancel is not None and cancel.is_set():
                raise CTFdError("Import cancelled.")
            if expired.is_set() or time.monotonic() >= deadline:
                raise CTFdError("The import time limit was reached.")
            chunk = response.read1(65536 if effective_maximum is None else min(65536, effective_maximum + 1 - received))
            if not chunk:
                break
            received += len(chunk)
            activity[0] = time.monotonic()
            if effective_maximum is not None and received > effective_maximum:
                raise CTFdError("The remote response exceeds the import size limit.")
            if writing:
                sink(chunk)
            else:
                content.extend(chunk)
        if expired.is_set():
            raise CTFdError("The remote request timed out.")
        if size and received != size:
            raise CTFdError("The remote response ended before its declared content length.")
        return Response(response.status, received_headers, bytes(content), cookies, received)
    except CTFdError as exc:
        exc.received_bytes = received
        raise
    except (OSError, http.client.HTTPException, UnicodeError) as exc:
        raise CTFdError("The remote request failed or timed out.", received_bytes=received) from exc
    finally:
        stopped.set()
        if response is not None:
            response.close()
        connection.close()


def attachment_name(url: str) -> str:
    name = unquote(urlsplit(url).path.rsplit("/", 1)[-1])
    name = re.sub(r"[\x00-\x1f\x7f/\\]", "_", name).strip(" .")[:240]
    return name or "attachment"


class LoginForm(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.forms = []
        self.current = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.current = {"action": attrs.get("action", ""), "method": attrs.get("method", "get").lower(), "fields": {}}
        elif tag == "input" and self.current is not None and attrs.get("name"):
            self.current["fields"][attrs["name"]] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form" and self.current is not None:
            self.forms.append(self.current)
            self.current = None

    def login(self):
        return next((form for form in self.forms if form["method"] == "post" and {"name", "password", "nonce"} <= form["fields"].keys()), None)


_SESSION_CSRF_NONCE = re.compile(
    r'''["']csrfNonce["']\s*:\s*(?P<quote>["'])(?P<nonce>[A-Za-z0-9_-]{16,4096})(?P=quote)'''
)


def session_csrf_nonce(document: str) -> str:
    """Read CTFd's post-login session nonce from its same-origin bootstrap."""

    if not isinstance(document, str) or len(document) > 16 * 1024 * 1024:
        return ""
    values = {match.group("nonce") for match in _SESSION_CSRF_NONCE.finditer(document)}
    return next(iter(values)) if len(values) == 1 else ""


class CTFdClient:
    def __init__(self, url: str, token: str = "", *, limits: Limits | None = None,
                 auth_type: str | None = None, username: str = "", password: str = "",
                 resolver: Callable = socket.getaddrinfo, transport: Callable = public_get):
        self.url = normalize_url(url, site=True)
        self.auth_type = ("token" if token else "none") if auth_type is None else auth_type
        if not isinstance(self.auth_type, str) or self.auth_type not in {"none", "token", "password"}:
            raise CTFdError("Unsupported CTFd authentication method.")
        self.token = token.strip() if self.auth_type == "token" else ""
        if len(self.token) > 4096 or not self.token.isascii() or re.search(r"[\x00-\x20\x7f]", self.token):
            raise CTFdError("Invalid CTFd access token.")
        if self.auth_type == "token" and not self.token:
            raise CTFdError("Enter a CTFd access token.")
        if (
            self.auth_type != "none"
            and origin(self.url)[0] != "https"
            and not insecure_http_credentials_allowed()
        ):
            raise CTFdError("Use HTTPS when supplying CTFd credentials.")
        self.username = username.strip() if self.auth_type == "password" else ""
        self.password = password if self.auth_type == "password" else ""
        if self.auth_type == "password" and (not self.username or not self.password or len(self.username) > 256 or len(self.password) > 4096):
            raise CTFdError("Enter a CTFd username and password.")
        self.cookies = http.cookiejar.CookieJar()
        self.csrf_nonce = ""
        self.logged_in = self.auth_type != "password"
        self.login_attempted = False
        self.limits = limits or Limits()
        self.resolver = resolver
        self.transport = transport
        self.deadline = time.monotonic() + self.limits.duration if self.limits.duration is not None else float("inf")
        self.downloaded = 0
        self.file_count = 0
        self.cancel_event = None
        self.rate_limit_until = 0.0

    def clear_credentials(self):
        self.token = self.username = self.password = ""
        self.csrf_nonce = ""
        self.cookies.clear()

    def _cookie_header(self, url):
        request = CookieRequest(url)
        self.cookies.add_cookie_header(request)
        value = request.get_header("Cookie", "")
        if len(value) > 16384:
            raise CTFdError("The CTFd cookie header is too large.")
        return value

    def _remember_cookies(self, url, response):
        if origin(url) != origin(self.url):
            return
        message = Message()
        for value in response.cookies:
            message.add_header("Set-Cookie", value)
        class CookieResponse:
            def info(self):
                return message
        self.cookies.extract_cookies(CookieResponse(), CookieRequest(url))

    def _request(self, url: str, maximum: int | None, *, api: bool = False,
                 method="GET", body=None, sink=None, on_headers=None, cancel=None,
                 extra_headers=None, same_origin=False, content_type=None,
                 referer=None, allow_error_status=False):
        cancel = cancel or self.cancel_event
        current = normalize_url(url)
        for redirect in range(self.limits.redirects + 1):
            if time.monotonic() < self.rate_limit_until:
                raise CTFdError("The CTFd site rate limited this connection. Please wait before retrying.")
            if cancel is not None and cancel.is_set():
                raise CTFdError("Import cancelled.")
            if time.monotonic() >= self.deadline:
                raise CTFdError("The import time limit was reached.")
            target = resolve_target(current, self.resolver)
            if (api or same_origin or method == "POST") and origin(current) != origin(self.url):
                raise CTFdError("CTFd API redirects must stay on the original site.")
            headers = {"Accept": "application/json" if api else "*/*",
                       "Accept-Encoding": "identity", "User-Agent": "CTF-Agent-Importer/1.0"}
            if self.token and origin(current) == origin(self.url):
                headers["Authorization"] = f"Token {self.token}"
            if origin(current) == origin(self.url):
                cookie = self._cookie_header(current)
                if cookie:
                    headers["Cookie"] = cookie
            if extra_headers:
                headers.update(extra_headers)
            if method == "POST":
                headers.update({
                    "Content-Type": content_type or "application/x-www-form-urlencoded",
                    "Origin": urlunsplit((urlsplit(self.url).scheme, urlsplit(self.url).netloc, "", "", "")),
                    "Referer": referer or self.url + "/login",
                })
            remaining = self.limits.total_bytes - self.downloaded if self.limits.total_bytes is not None else None
            if remaining is not None and remaining <= 0:
                raise CTFdError("The total import size limit was reached.")
            maximum_now = min(maximum, remaining) if maximum is not None and remaining is not None else maximum if remaining is None else remaining
            try:
                options = {}
                if method != "GET" or body is not None:
                    options.update(method=method, body=body)
                if sink is not None:
                    options.update(sink=sink, on_headers=on_headers, cancel=cancel)
                elif cancel is not None:
                    options["cancel"] = cancel
                response = self.transport(target, headers, maximum_now,
                                          min(self.limits.timeout, max(0.1, self.deadline - time.monotonic())), self.deadline, **options)
            except CTFdError as exc:
                # Failed/truncated/slow streams still consume the cumulative
                # byte budget; otherwise repeated failures bypass that limit.
                self.downloaded += exc.received_bytes
                raise
            # Also enforce limits for injectable transports used by tests.
            self.downloaded += response.received_bytes or len(response.content)
            if maximum_now is not None and len(response.content) > maximum_now:
                raise CTFdError("The remote response exceeds the import size limit.")
            self._remember_cookies(current, response)
            if response.status in {301, 302, 303, 307, 308}:
                location = response.headers.get("location")
                if not location or redirect == self.limits.redirects:
                    raise CTFdError("The remote redirect limit was reached.")
                next_url = normalize_url(urljoin(current, location))
                if origin(current)[0] == "https" and origin(next_url)[0] != "https":
                    raise CTFdError("HTTPS redirects may not downgrade to HTTP.")
                if method == "POST":
                    if response.status in {307, 308}:
                        raise CTFdError("The login endpoint requested an unsupported credential redirect.")
                    method, body = "GET", None
                current = next_url
                continue
            if response.status == 429:
                delay = response.headers.get("retry-after", "")
                self.rate_limit_until = time.monotonic() + (max(1, int(delay)) if delay.isdigit() and len(delay) <= 8 else 30)
                if allow_error_status:
                    return response, current
                suffix = f" Retry after {int(delay)} seconds." if delay.isdigit() and len(delay) <= 8 else " Please wait before trying again."
                raise CTFdError("The CTFd site rate limited this request." + suffix)
            if response.status in {401, 403}:
                if allow_error_status:
                    return response, current
                if response.headers.get("content-type", "").split(";", 1)[0].strip().lower() == "application/json":
                    try:
                        error = json.loads(response.content)
                    except (ValueError, UnicodeError):
                        error = None
                    code = error.get("code") if isinstance(error, dict) else None
                    if code == "competition_closed":
                        raise CTFdError("The CTFd site has not opened challenge access yet or the competition has closed.")
                    if code == "login_required" and self.auth_type == "token":
                        raise CTFdError("The CTFd site did not accept this access token. Check the token or use username and password.")
                raise CTFdError("CTFd denied access. Check the selected authentication method and challenge visibility.")
            if not 200 <= response.status < 300:
                if allow_error_status:
                    return response, current
                raise CTFdError(f"The remote server returned HTTP {response.status}.")
            return response, current
        raise CTFdError("The remote redirect limit was reached.")

    def _get(self, url: str, maximum: int | None, *, api=False):
        return self._request(url, maximum, api=api)[0].content

    def authenticate(self):
        if self.logged_in:
            return
        if self.login_attempted:
            raise CTFdError("CTFd login failed. Start a new connection to try again.")
        self.login_attempted = True
        try:
            response, login_url = self._request(self.url + "/login", self.limits.json_bytes, same_origin=True)
            parser = LoginForm()
            login_html = response.content.decode("utf-8", errors="replace")
            parser.feed(login_html)
            form = parser.login()
            if not form or not form["fields"]["nonce"] or len(form["fields"]["nonce"]) > 4096:
                # Some CTFd-compatible sites use a Next.js login page and a
                # same-origin JSON session API instead of CTFd's HTML form.
                # Require its bootstrap marker before sending credentials to
                # that endpoint so unrelated SSO/CAPTCHA pages still fail.
                if ("window.__ctfdInitialRequests" in login_html
                        and '"/api/v2/auth/check/cookie"' in login_html):
                    self._authenticate_json_session()
                    return
                raise CTFdError("The site does not expose the supported CTFd password login form. Use an API token if SSO or CAPTCHA is required.")
            # The login-form nonce proves the credential POST, but CTFd
            # rotates the session nonce after a successful login.  Keep the
            # two values separate: state-changing API requests must use the
            # authenticated session nonce rendered by the destination page.
            self.csrf_nonce = ""
            action = normalize_url(urljoin(login_url, form["action"]))
            if origin(action) != origin(self.url) or urlsplit(action).path.rstrip("/") != urlsplit(self.url + "/login").path.rstrip("/"):
                raise CTFdError("The CTFd login form points to an unexpected endpoint.")
            payload = urlencode({"name": self.username, "password": self.password, "nonce": form["fields"]["nonce"]}).encode("ascii")
            response, final_url = self._request(action, self.limits.json_bytes, method="POST", body=payload, same_origin=True)
            after = LoginForm()
            authenticated_html = response.content.decode("utf-8", errors="replace")
            after.feed(authenticated_html)
            if after.login() or urlsplit(final_url).path.rstrip("/") == urlsplit(action).path.rstrip("/"):
                raise CTFdError("CTFd login failed. Check the username and password or use an API token for this site.")
            self.csrf_nonce = session_csrf_nonce(authenticated_html)
            self.logged_in = True
        finally:
            self.username = self.password = ""

    def _authenticate_json_session(self):
        credentials = json.dumps(
            {"name": self.username, "password": self.password},
            ensure_ascii=False, separators=(",", ":"),
        ).encode("utf-8")
        for endpoint in ("/api/v2/auth/login/prepare", "/api/v2/auth/login"):
            response, _ = self._request(
                self.url + endpoint, self.limits.json_bytes, api=True,
                method="POST", body=credentials, same_origin=True,
                content_type="application/json", allow_error_status=True,
            )
            try:
                payload = json.loads(response.content)
            except (ValueError, UnicodeError):
                payload = None
            if not isinstance(payload, dict):
                raise CTFdError("The CTFd JSON login endpoint returned an unsupported response.")
            if endpoint.endswith("/prepare") and isinstance(payload.get("data"), dict) and payload["data"].get("needs_consent") is True:
                raise CTFdError("Complete the CTFd site's consent step in your browser before connecting.")
            if response.status != 200 or payload.get("success") is not True:
                raise CTFdError("CTFd login failed. Check the username and password or complete any required browser steps.")
        current = self._json(self.url + "/api/v1/users/me")
        if not isinstance(current, dict):
            raise CTFdError("The site did not confirm the authenticated CTFd session.")
        self.logged_in = True

    def _json(self, url: str):
        content = self._get(url, self.limits.json_bytes, api=True)
        try:
            payload = json.loads(content)
        except (ValueError, UnicodeError) as exc:
                raise CTFdError("The site did not return a CTFd JSON response. Check the base URL and selected authentication method.") from exc
        if not isinstance(payload, dict) or payload.get("success") is not True or "data" not in payload:
            raise CTFdError("The site returned an unsuccessful or unsupported CTFd response.")
        return payload["data"]

    def validate(self) -> None:
        """Validate authentication without importing data or mutating CTFd."""

        self.authenticate()
        current = self._json(self.url + "/api/v1/users/me")
        if not isinstance(current, dict):
            raise CTFdError("The site returned an unsupported CTFd account response.")

    def challenge_solved_by_me(self, challenge_id: int) -> bool:
        """Return CTFd's authenticated solve state without mutating the event."""

        if type(challenge_id) is not int or challenge_id < 1:
            raise CTFdError("The CTFd challenge ID is invalid.")
        self.authenticate()
        challenge = self._json(f"{self.url}/api/v1/challenges/{challenge_id}")
        if (
            not isinstance(challenge, dict)
            or challenge.get("id") != challenge_id
            or type(challenge.get("solved_by_me")) is not bool
        ):
            raise CTFdError(
                "The CTFd challenge detail did not include a trustworthy solve state."
            )
        return challenge["solved_by_me"]

    def submit(self, challenge_id: int, submission: str) -> dict:
        """Submit one flag through CTFd's documented attempt API.

        Password sessions need the CSRF nonce used by the authenticated web
        session. API tokens do not, but sending no empty CSRF header keeps the
        two credential modes explicit.
        """

        if type(challenge_id) is not int or challenge_id < 1:
            raise CTFdError("The CTFd challenge ID is invalid.")
        if not isinstance(submission, str) or not submission or len(submission) > 4000:
            raise CTFdError("The flag is empty or exceeds the supported length.")
        self.authenticate()
        payload = json.dumps(
            {"challenge_id": challenge_id, "submission": submission},
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
        headers = {}
        if self.auth_type == "password":
            nonce = getattr(self, "csrf_nonce", "")
            if not nonce:
                raise CTFdError("The CTFd password session did not provide a CSRF token.")
            headers["CSRF-Token"] = nonce
        response, _ = self._request(
            self.url + "/api/v1/challenges/attempt",
            self.limits.json_bytes,
            api=True,
            method="POST",
            body=payload,
            extra_headers=headers,
            same_origin=True,
            content_type="application/json",
            referer=self.url + "/challenges",
            allow_error_status=True,
        )
        try:
            result = json.loads(response.content)
        except (ValueError, UnicodeError):
            if response.status in {401, 403}:
                raise CTFdError("CTFd denied the flag submission. Check the stored authentication method.") from None
            if response.status == 429:
                return {"status": "rate_limited", "message": "CTFd rate limited the flag submission."}
            raise CTFdError(f"The CTFd submission endpoint returned HTTP {response.status} without a supported JSON response.") from None
        data = result.get("data") if isinstance(result, dict) and result.get("success") is True else None
        status = data.get("status") if isinstance(data, dict) else None
        if not isinstance(status, str) or len(status) > 80:
            if response.status in {401, 403}:
                raise CTFdError("CTFd denied the flag submission. Check the stored authentication method.")
            if response.status == 429:
                return {"status": "rate_limited", "message": "CTFd rate limited the flag submission."}
            raise CTFdError("The CTFd submission endpoint returned an unsupported response.")
        message = data.get("message", "")
        if not isinstance(message, str):
            message = ""
        # Remote messages can contain plugin-controlled detail. Keep only a
        # small, control-character-free display value and never include it in
        # local exception or audit logs.
        message = "".join(char for char in message if char in "\n\t" or ord(char) >= 32)[:1000]
        return {"status": status.lower(), "message": message}

    def preview(self, challenge_ids: list[int] | None = None, *, metadata_only=False,
                exclude_ids: set[int] | None = None) -> dict:
        self.authenticate()
        listing = self._json(self.url + "/api/v1/challenges")
        if not isinstance(listing, list):
            raise CTFdError("The CTFd challenge list has an unsupported format.")
        chosen = set(challenge_ids) if challenge_ids is not None else None
        excluded = exclude_ids or set()
        challenges, errors = [], []
        seen = set()
        for row in listing:
            if self.cancel_event is not None and self.cancel_event.is_set():
                raise CTFdError("Import cancelled.")
            if not isinstance(row, dict) or type(row.get("id")) is not int or row["id"] < 1:
                errors.append({"challenge_id": None, "message": "Skipped a challenge with an invalid ID."})
                continue
            challenge_id = row["id"]
            if (
                challenge_id in seen or challenge_id in excluded
                or (chosen is not None and challenge_id not in chosen)
            ):
                continue
            if len(seen) >= self.limits.challenges:
                errors.append({"challenge_id": None, "message": f"At most {self.limits.challenges} challenges can be imported at once."})
                break
            seen.add(challenge_id)
            if metadata_only:
                challenges.append({"id": challenge_id, "name": str(row.get("name") or f"Challenge {challenge_id}")[:200],
                                   "category": str(row.get("category") or "")[:100], "description": "",
                                   "remote": connection_info(row.get("connection_info")), "files": []})
                continue
            try:
                detail = self._json(f"{self.url}/api/v1/challenges/{challenge_id}")
                if not isinstance(detail, dict) or detail.get("id") != challenge_id:
                    raise CTFdError("The challenge detail ID did not match the list.")
                if detail.get("type") == "hidden":
                    raise CTFdError("The challenge is locked or hidden on the source site.")
                files = detail.get("files") or []
                if not isinstance(files, list):
                    raise CTFdError("The challenge attachment list has an unsupported format.")
                if len(files) > self.limits.files_per_challenge:
                    errors.append({"challenge_id": challenge_id, "message": f"Attachment list limited to {self.limits.files_per_challenge} files."})
                attachments = []
                for file in files[:self.limits.files_per_challenge]:
                    try:
                        if not isinstance(file, str):
                            raise CTFdError("Skipped an attachment with an unsupported URL.")
                        file_url = normalize_url(urljoin(self.url + "/", file))
                        attachments.append({"url": file_url, "name": attachment_name(file_url)})
                    except CTFdError as exc:
                        errors.append({"challenge_id": challenge_id, "message": str(exc)})
                challenges.append({"id": challenge_id,
                                   "name": str(detail.get("name") or f"Challenge {challenge_id}")[:200],
                                   "category": str(detail.get("category") or "")[:100],
                                   "description": str(detail.get("description") or "")[:200000],
                                   "remote": connection_info(detail.get("connection_info")),
                                   "files": attachments})
            except CTFdError as exc:
                errors.append({"challenge_id": challenge_id, "message": str(exc)})
                if time.monotonic() < self.rate_limit_until:
                    break
        if chosen is not None:
            missing = chosen - seen - excluded
            if missing:
                errors.append({"challenge_id": None, "message": "Some selected challenges were not visible or exceeded the import limit."})
        result = {"source_url": self.url, "challenges": challenges, "errors": errors}
        if metadata_only:
            result["details_pending"] = True
        return result

    def download(self, url: str) -> bytes:
        if self.file_count >= self.limits.files:
            raise CTFdError("The attachment count limit was reached.")
        self.file_count += 1
        return self._get(url, self.limits.file_bytes)

    def download_to(self, url: str, partial: Path, *, validator="", progress=None, cancel=None,
                    storage_budget=None, storage_reservation=None):
        """Stream into an operation-owned file; resume only with an entity validator."""
        self.authenticate()
        if self.file_count >= self.limits.files:
            raise CTFdError("The attachment count limit was reached.")
        self.file_count += 1
        if partial.is_symlink():
            raise CTFdError("Invalid partial attachment path.")
        if storage_budget is not None and not partial.resolve().is_relative_to(storage_budget.data_dir):
            raise CTFdError("Invalid partial attachment path for the data volume.")
        if validator and (not validator.startswith(("etag:", "last-modified:")) or len(validator) > 4096 or
                          not validator.isascii() or re.search(r"[\x00-\x1f\x7f]", validator)):
            validator = ""
        previous = partial.stat().st_size if partial.exists() else 0
        offset = previous if validator else 0
        digest = hashlib.sha256()
        if offset:
            with partial.open("rb") as prefix:
                while chunk := prefix.read(1024 * 1024):
                    if cancel is not None and cancel.is_set():
                        raise CTFdError("Import cancelled.")
                    digest.update(chunk)
        state = {"bytes": offset, "total": None, "validator": validator}
        reservation_key = ""
        reservation_scope = None
        if storage_budget is not None:
            if (not isinstance(storage_reservation, tuple) or len(storage_reservation) != 4 or
                    any(not isinstance(value, str) or not value for value in storage_reservation[:3]) or
                    (storage_reservation[3] is not None and
                     (not isinstance(storage_reservation[3], str) or not storage_reservation[3]))):
                raise CTFdError("Invalid local storage reservation scope.")
            reservation_key = storage_reservation[0]
            reservation_scope = storage_reservation[1:]
        invalid_range = [False]
        headers = {"Range": f"bytes={offset}-", "If-Range": validator.split(":", 1)[1]} if offset else {}
        with partial.open("r+b" if partial.exists() else "x+b") as output:
            def report():
                output.flush()
                if progress:
                    progress(state["bytes"], state["total"], state["validator"])

            def receive_headers(status, received):
                nonlocal digest
                if cancel is not None and cancel.is_set():
                    raise CTFdError("Import cancelled.")
                if status == 206:
                    match = re.fullmatch(r"bytes (\d+)-(\d+)/(\d+)", received.get("content-range", ""))
                    if not offset or not match or int(match[1]) != offset or int(match[2]) < int(match[1]) or int(match[3]) <= int(match[2]):
                        invalid_range[0] = True
                        raise CTFdError("The remote server returned an invalid download range. Retry with a fresh download.")
                    state["total"] = int(match[3])
                    if state["total"] > MAX_SQLITE_INTEGER:
                        raise CTFdError("The remote attachment length is invalid.")
                    if validator.startswith("etag:") and received.get("etag") != validator[5:]:
                        invalid_range[0] = True
                        raise CTFdError("The remote attachment changed while resuming. Retry with a fresh download.")
                    if validator.startswith("last-modified:") and received.get("last-modified") != validator[14:]:
                        invalid_range[0] = True
                        raise CTFdError("The remote attachment changed while resuming. Retry with a fresh download.")
                    output.seek(offset)
                elif status == 200:
                    output.seek(0)
                    output.truncate()
                    output.flush()
                    os.fsync(output.fileno())
                    state["bytes"] = 0
                    digest = hashlib.sha256()
                    length = received.get("content-length")
                    try:
                        state["total"] = int(length) if length is not None else None
                    except (TypeError, ValueError) as exc:
                        raise CTFdError("The remote attachment length is invalid.") from exc
                    if state["total"] is not None and not 0 <= state["total"] <= MAX_SQLITE_INTEGER:
                        raise CTFdError("The remote attachment length is invalid.")
                else:
                    raise CTFdError("The remote server returned an unsupported download response.")
                etag = received.get("etag", "")
                modified = received.get("last-modified", "")
                state["validator"] = "etag:" + etag if etag and not etag.startswith("W/") else "last-modified:" + modified if modified else ""
                if len(state["validator"]) > 4096 or not state["validator"].isascii() or re.search(r"[\x00-\x1f\x7f]", state["validator"]):
                    state["validator"] = ""
                if storage_budget is not None:
                    try:
                        if state["total"] is None:
                            storage_budget.release(reservation_key)
                        else:
                            storage_budget.reserve(
                                reservation_key, "ctfd", reservation_scope[0],
                                reservation_scope[1], reservation_scope[2],
                                max(0, state["total"] - state["bytes"]),
                            )
                    except StorageBudgetError as exc:
                        raise CTFdError(str(exc)) from None
                elif state["total"] is not None and shutil.disk_usage(partial.parent).free < max(0, state["total"] - state["bytes"]) + 1024 * 1024:
                    raise CTFdError("The data volume has insufficient free space for this attachment.")
                report()

            last_report = [time.monotonic()]
            def receive(chunk):
                if cancel is not None and cancel.is_set():
                    raise CTFdError("Import cancelled.")
                def durable_write():
                    output.write(chunk)
                    output.flush()
                    os.fsync(output.fileno())
                if storage_budget is not None:
                    try:
                        if state["total"] is None:
                            storage_budget.write_unreserved(len(chunk), durable_write)
                        else:
                            storage_budget.commit_reserved_write(
                                reservation_key, len(chunk), durable_write
                            )
                    except StorageBudgetError as exc:
                        raise CTFdError(str(exc), received_bytes=state["bytes"] - offset) from None
                    except OSError as exc:
                        raise CTFdError(
                            "데이터 저장 공간에 첨부파일을 기록할 수 없습니다.",
                            received_bytes=state["bytes"] - offset,
                        ) from exc
                else:
                    if shutil.disk_usage(partial.parent).free < len(chunk) + 1024 * 1024:
                        raise CTFdError("The data volume has insufficient free space.")
                    output.write(chunk)
                digest.update(chunk)
                state["bytes"] += len(chunk)
                if time.monotonic() - last_report[0] >= .25:
                    report()
                    last_report[0] = time.monotonic()
            try:
                try:
                    self._request(url, self.limits.file_bytes, sink=receive, on_headers=receive_headers,
                                  cancel=cancel, extra_headers=headers)
                except CTFdError as exc:
                    if not offset or (str(exc) != "The remote server returned HTTP 416." and not invalid_range[0]):
                        raise
                    # A complete partial or changed remote range can produce 416.
                    # A plain GET restarts atomically instead of trusting old bytes.
                    offset = 0
                    validator = ""
                    self._request(url, self.limits.file_bytes, sink=receive, on_headers=receive_headers, cancel=cancel)
                if state["total"] is not None and state["bytes"] != state["total"]:
                    raise CTFdError("The downloaded attachment is incomplete.")
                output.flush()
                os.fsync(output.fileno())
            finally:
                report()
        return {**state, "sha256": digest.hexdigest()}


JOB_SCHEMA = """
CREATE TABLE IF NOT EXISTS ctfd_jobs (
 id TEXT PRIMARY KEY, owner_user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 source_url TEXT NOT NULL, auth_type TEXT NOT NULL, selected_ids TEXT,
 mode TEXT NOT NULL DEFAULT 'import', target_challenge_id TEXT,
 status TEXT NOT NULL, imported INTEGER NOT NULL DEFAULT 0, skipped INTEGER NOT NULL DEFAULT 0,
 refreshed INTEGER NOT NULL DEFAULT 0,
 attachments INTEGER NOT NULL DEFAULT 0, downloaded_bytes INTEGER NOT NULL DEFAULT 0,
 current_file TEXT NOT NULL DEFAULT '', total_bytes INTEGER, errors TEXT NOT NULL DEFAULT '[]',
 cancel_requested INTEGER NOT NULL DEFAULT 0 CHECK(cancel_requested IN (0,1)),
 created_at TEXT NOT NULL, updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ctfd_jobs_owner ON ctfd_jobs(owner_user_id,workspace_id,created_at);
CREATE TABLE IF NOT EXISTS ctfd_job_challenges (
 job_id TEXT NOT NULL REFERENCES ctfd_jobs(id) ON DELETE CASCADE, remote_id INTEGER NOT NULL,
 challenge_id TEXT NOT NULL REFERENCES challenges(id) ON DELETE CASCADE, skipped INTEGER NOT NULL,
 PRIMARY KEY(job_id,remote_id)
);
CREATE TABLE IF NOT EXISTS ctfd_job_files (
 id TEXT PRIMARY KEY, job_id TEXT NOT NULL REFERENCES ctfd_jobs(id) ON DELETE CASCADE,
 challenge_id TEXT NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
 remote_id INTEGER NOT NULL, file_index INTEGER NOT NULL, original_name TEXT NOT NULL,
 url_hash TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', bytes INTEGER NOT NULL DEFAULT 0,
 total INTEGER, validator TEXT NOT NULL DEFAULT '', sha256 TEXT NOT NULL DEFAULT '',
 UNIQUE(job_id,remote_id,file_index)
);
CREATE TABLE IF NOT EXISTS ctfd_managed_attachments (
 attachment_id TEXT PRIMARY KEY REFERENCES attachments(id) ON DELETE CASCADE,
 workspace_id TEXT NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
 challenge_id TEXT NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
 source_url TEXT NOT NULL, remote_id INTEGER NOT NULL, file_index INTEGER NOT NULL,
 url_hash TEXT NOT NULL, sha256 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_ctfd_managed_challenge
 ON ctfd_managed_attachments(workspace_id,challenge_id,source_url,remote_id);
"""


class _ImportCancellation:
    """Cancellation visible both to this thread and overlapping processes."""

    def __init__(self, marker: Path, *additional_markers: Path):
        self.marker = marker
        self.markers = (marker, *additional_markers)
        self.local = threading.Event()

    def set(self) -> None:
        self.local.set()
        for marker in self.markers:
            marker.parent.mkdir(parents=True, exist_ok=True)
            flags = os.O_WRONLY | os.O_CREAT
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(marker, flags, 0o600)
            os.close(descriptor)

    def is_set(self) -> bool:
        return self.local.is_set() or any(marker.is_file() for marker in self.markers)


def _now():
    return datetime.now(timezone.utc).isoformat()


class ImportJobs:
    """Durable import metadata; credentials and signed URLs exist only in memory."""

    def __init__(self, app, settings):
        self.app, self.settings = app, settings
        self._storage_layout = getattr(app.state, "storage_layout", None)
        self.lock = threading.RLock()
        # Preview is synchronous network work executed by AnyIO's shared
        # worker pool.  Keep a small, nonblocking service-specific allowance
        # so one account (or a handful of slow CTFd sites) cannot occupy every
        # worker thread used by the rest of the web application.
        self.preview_slot_lock = threading.Lock()
        self.preview_inflight_total = 0
        self.preview_inflight_by_owner = {}
        self.preview_cancellations = {}
        self.previews = {}
        self.workers = {}
        self.stopping = False
        self.janitor_stop = threading.Event()
        lock_base = Path(getattr(settings, "config_dir", settings.data_dir))
        self.lock_root = lock_base / ".locks" / "ctfd-imports"
        self.lock_root.mkdir(parents=True, exist_ok=True)
        with self.db() as db:
            db.executescript(JOB_SCHEMA)
            columns = {row[1] for row in db.execute("PRAGMA table_info(ctfd_jobs)")}
            if "cancel_requested" not in columns:
                db.execute(
                    "ALTER TABLE ctfd_jobs ADD COLUMN cancel_requested INTEGER NOT NULL DEFAULT 0"
                )
            if "mode" not in columns:
                db.execute(
                    "ALTER TABLE ctfd_jobs ADD COLUMN mode TEXT NOT NULL DEFAULT 'import'"
                )
            if "target_challenge_id" not in columns:
                db.execute("ALTER TABLE ctfd_jobs ADD COLUMN target_challenge_id TEXT")
            if "refreshed" not in columns:
                db.execute(
                    "ALTER TABLE ctfd_jobs ADD COLUMN refreshed INTEGER NOT NULL DEFAULT 0"
                )
            # Attachments imported by older releases can be identified exactly:
            # their public attachment id is the durable job-file id.  Backfill
            # that provenance once so later refreshes never touch manual files.
            db.execute(
                """INSERT OR IGNORE INTO ctfd_managed_attachments
                   (attachment_id,workspace_id,challenge_id,source_url,remote_id,
                    file_index,url_hash,sha256)
                   SELECT a.id,a.workspace_id,a.challenge_id,j.source_url,f.remote_id,
                          f.file_index,f.url_hash,f.sha256
                     FROM ctfd_job_files f
                     JOIN ctfd_jobs j ON j.id=f.job_id
                     JOIN attachments a ON a.id=f.id
                    WHERE f.status='done'"""
            )
        self.budget = get_storage_budget(app, settings)
        self._recover_abandoned_jobs()
        self.cleanup_terminal_refresh_staging()
        self.janitor = threading.Thread(target=self.clean_expired, name="ctfd-preview-expiry", daemon=True)
        self.janitor.start()

    def clean_expired(self):
        while not self.janitor_stop.wait(30):
            with self.lock:
                self.expire()
            try:
                self.cleanup_terminal_refresh_staging()
            except (OSError, sqlite3.Error):
                pass

    @contextmanager
    def db(self):
        connection = self.app.state.connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @property
    def layout(self):
        if self._storage_layout is None:
            from .storage_layout import StorageLayout
            self._storage_layout = StorageLayout(self.settings, self.db)
            self.app.state.storage_layout = self._storage_layout
        return self._storage_layout

    def _job_lock(self, job_id: str) -> ProcessFileLock:
        name = hashlib.sha256(job_id.encode("utf-8")).hexdigest() + ".lock"
        return ProcessFileLock(self.lock_root / name)

    def _cancel_marker(self, job_id: str) -> Path:
        name = hashlib.sha256(job_id.encode("utf-8")).hexdigest() + ".cancel"
        return self.lock_root / name

    def _preview_lock(self, owner_user_id: str) -> ProcessFileLock:
        name = "preview-" + hashlib.sha256(owner_user_id.encode("utf-8")).hexdigest() + ".lock"
        return ProcessFileLock(self.lock_root / name)

    def _preview_cancel_marker(self, owner_user_id: str) -> Path:
        name = "preview-" + hashlib.sha256(owner_user_id.encode("utf-8")).hexdigest() + ".cancel"
        return self.lock_root / name

    def _workspace_preview_lock(self, workspace_id: str) -> ProcessFileLock:
        name = "preview-workspace-" + hashlib.sha256(workspace_id.encode("utf-8")).hexdigest() + ".lock"
        return ProcessFileLock(self.lock_root / name)

    def _workspace_preview_cancel_marker(self, workspace_id: str) -> Path:
        name = "preview-workspace-" + hashlib.sha256(workspace_id.encode("utf-8")).hexdigest() + ".cancel"
        return self.lock_root / name

    def _signal_job(self, job_id: str) -> None:
        _ImportCancellation(self._cancel_marker(job_id)).set()

    def _recover_abandoned_jobs(self) -> None:
        """Recover only jobs whose cross-process writer lock is unowned."""

        with self.db() as db:
            rows = db.execute(
                """SELECT id,workspace_id,owner_user_id,mode
                     FROM ctfd_jobs WHERE status IN ('queued','running')"""
            ).fetchall()
        for row in rows:
            lease = self._job_lock(row["id"])
            if not lease.try_acquire():
                continue
            try:
                with self.db() as db:
                    db.execute("BEGIN IMMEDIATE")
                    changed = db.execute(
                        """UPDATE ctfd_jobs SET status='interrupted',cancel_requested=1,
                             current_file='',updated_at=?
                           WHERE id=? AND status IN ('queued','running')""",
                        (_now(), row["id"]),
                    ).rowcount
                if changed and row["mode"] == "refresh":
                    try:
                        cleaned = self._discard_refresh_generation(
                            row["id"], row["workspace_id"], row["owner_user_id"]
                        )
                    except (OSError, sqlite3.Error):
                        cleaned = False
                    if cleaned:
                        self.release_job_reservations(row["id"])
                elif changed:
                    self.release_job_reservations(row["id"])
            finally:
                lease.release()

    def check_owner(self, workspace_id, user):
        return self.app.state.require_workspace_owner(workspace_id, user)

    def workspace_lock(self, workspace_id):
        uploads = getattr(self.app.state, "uploads", None)
        return uploads.workspace_lock(workspace_id) if uploads else nullcontext()

    @contextmanager
    def workspace_slot(self, workspace_id):
        """Acquire the local workspace lifecycle lock without tying up a worker."""

        uploads = getattr(self.app.state, "uploads", None)
        if uploads is not None and hasattr(uploads, "try_workspace_lock"):
            with uploads.try_workspace_lock(workspace_id):
                yield
            return
        lock = self.workspace_lock(workspace_id)
        acquire = getattr(lock, "acquire", None)
        if not callable(acquire):
            with lock:
                yield
            return
        if not acquire(blocking=False):
            from fastapi import HTTPException

            raise HTTPException(409, "This workspace is busy. Try again shortly.")
        try:
            yield
        finally:
            lock.release()

    @contextmanager
    def preview_slot(self, owner_user_id, workspace_id=None):
        """Reserve one remote-preview slot without waiting for a thread."""
        from fastapi import HTTPException

        with self.preview_slot_lock:
            if self.preview_inflight_by_owner.get(owner_user_id, 0) >= 1:
                raise HTTPException(409, "This account already has a CTFd preview in progress.")
            if self.preview_inflight_total >= 4:
                raise HTTPException(429, "The CTFd preview service is busy. Try again shortly.")
            self.preview_inflight_total += 1
            self.preview_inflight_by_owner[owner_user_id] = 1
        lease = self._preview_lock(owner_user_id)
        if not lease.try_acquire():
            with self.preview_slot_lock:
                self.preview_inflight_total -= 1
                self.preview_inflight_by_owner.pop(owner_user_id, None)
            raise HTTPException(409, "This account already has a CTFd preview in progress.")
        workspace_lease = self._workspace_preview_lock(workspace_id) if workspace_id else None
        if workspace_lease is not None and not workspace_lease.try_acquire():
            lease.release()
            with self.preview_slot_lock:
                self.preview_inflight_total -= 1
                self.preview_inflight_by_owner.pop(owner_user_id, None)
            raise HTTPException(409, "This workspace already has a CTFd preview in progress.")
        markers = [self._preview_cancel_marker(owner_user_id)]
        if workspace_id:
            markers.append(self._workspace_preview_cancel_marker(workspace_id))
        try:
            for marker in markers:
                marker.unlink(missing_ok=True)
            cancellation = _ImportCancellation(*markers)
        except BaseException:
            if workspace_lease is not None:
                workspace_lease.release()
            lease.release()
            with self.preview_slot_lock:
                self.preview_inflight_total -= 1
                self.preview_inflight_by_owner.pop(owner_user_id, None)
            raise
        with self.preview_slot_lock:
            self.preview_cancellations[owner_user_id] = (workspace_id, cancellation)
        try:
            yield cancellation
        finally:
            with self.preview_slot_lock:
                self.preview_inflight_total -= 1
                self.preview_inflight_by_owner.pop(owner_user_id, None)
                current = self.preview_cancellations.get(owner_user_id)
                if current is not None and current[1] is cancellation:
                    self.preview_cancellations.pop(owner_user_id, None)
            if workspace_lease is not None:
                workspace_lease.release()
            lease.release()

    def check_active(self, workspace_id, owner):
        with self.db() as db:
            active = db.execute(
                """SELECT 1 FROM workspaces w JOIN users u ON u.id=w.owner_user_id
                   WHERE w.id=? AND w.owner_user_id=? AND u.active=1""",
                (workspace_id, owner),
            ).fetchone()
        if not active:
            raise CTFdError("The workspace or user is no longer available.")

    def get(self, workspace_id, user, job_id):
        from fastapi import HTTPException
        self.check_owner(workspace_id, user)
        with self.db() as db:
            row = db.execute("SELECT * FROM ctfd_jobs WHERE id=? AND workspace_id=? AND owner_user_id=?",
                             (job_id, workspace_id, user["id"])).fetchone()
        if not row:
            raise HTTPException(404, "CTFd import job not found.")
        result = dict(row)
        result["errors"] = json.loads(result["errors"])
        # Attachment lengths arrive independently; do not present one file's
        # length as the total for a multi-file job.
        result["current_file_total"] = result["total_bytes"]
        result["total_bytes"] = result["downloaded_bytes"] if result["status"] == "completed" else None
        result.pop("selected_ids")
        result.pop("owner_user_id")
        return result

    def update(self, job_id, **fields):
        fields["updated_at"] = _now()
        with self.db() as db:
            db.execute("UPDATE ctfd_jobs SET " + ",".join(key + "=?" for key in fields) + " WHERE id=?",
                       (*fields.values(), job_id))

    def client(self, body):
        if not isinstance(body.get("url"), str):
            raise CTFdError("Enter a CTFd site URL.")
        for key, maximum in (("token", 4096), ("username", 256), ("password", 4096)):
            if not isinstance(body.get(key, ""), str) or len(body.get(key, "")) > maximum:
                raise CTFdError("The CTFd authentication fields have an unsupported format.")
        auth_type = body.get("auth_type")
        factory = getattr(self.app.state, "ctfd_client_factory", CTFdClient)
        return factory(url=body["url"], token=body.get("token", ""), auth_type=auth_type,
                       username=body.get("username", ""), password=body.get("password", ""))

    def saved_client(self, workspace_id, user):
        service = getattr(self.app.state, "ctfd_submit", None)
        if service is None or not hasattr(service, "client_for_import"):
            from fastapi import HTTPException

            raise HTTPException(409, "CTFd 연결을 먼저 저장한 뒤 다시 시도하세요.")
        client = service.client_for_import(workspace_id, user)
        generation = self.saved_connection_generation(client)
        if not isinstance(generation, str) or not re.fullmatch(
            r"[0-9a-f]{32}", generation
        ):
            client.clear_credentials()
            raise CTFdError(
                "The saved CTFd connection cannot be bound to this import. "
                "Save the connection again."
            )
        return client

    @staticmethod
    def saved_connection_generation(client):
        generation = getattr(client, "saved_connection_generation", None)
        return generation if isinstance(generation, str) else None

    def require_current_saved_connection(
        self, database, workspace_id, owner_user_id, client, generation
    ):
        """Bind a borrowed credential to the connection used by its preview."""

        if generation is None:
            return
        service = getattr(self.app.state, "ctfd_submit", None)
        checker = getattr(service, "import_connection_matches", None)
        if not callable(checker) or not checker(
            workspace_id,
            owner_user_id,
            client.url,
            generation,
            connection=database,
        ):
            raise CTFdError(
                "The saved CTFd connection changed after this preview. Preview again."
            )

    def request_client(self, workspace_id, user, body, *, allow_saved=False):
        if body.get("preview_id"):
            raise CTFdError("A preview client must be consumed through its preview ID.")
        if body.get("url") is not None:
            return self.client(body)
        if allow_saved:
            return self.saved_client(workspace_id, user)
        return self.client(body)

    @staticmethod
    def selected(body):
        value = body.get("challenge_ids")
        if value is not None and (not isinstance(value, list) or not value or len(value) > 100 or
                                  any(type(item) is not int or item <= 0 for item in value)):
            raise CTFdError("Select between 1 and 100 valid challenge IDs, or omit the selection.")
        return list(dict.fromkeys(value)) if value is not None else None

    def bound_challenges(self, workspace_id, source):
        """Return the local remote-id mapping for one canonical CTFd source."""

        with self.db() as db:
            rows = db.execute(
                """SELECT id,ctfd_id,ctfd_url FROM challenges
                    WHERE workspace_id=? AND ctfd_id IS NOT NULL AND ctfd_url IS NOT NULL""",
                (workspace_id,),
            ).fetchall()
        result = {}
        for row in rows:
            try:
                same_source = normalize_url(row["ctfd_url"], site=True) == source
            except CTFdError:
                same_source = False
            if same_source:
                result[row["ctfd_id"]] = row["id"]
        return result

    def require_bound_source(self, workspace_id, source):
        bound = self.bound_challenges(workspace_id, source)
        if not bound:
            raise CTFdError(
                "The saved CTFd connection is not the source of any challenge in this workspace."
            )
        return bound

    def refresh_target(self, workspace_id, challenge_id):
        with self.db() as db:
            row = db.execute(
                """SELECT id,ctfd_id,ctfd_url FROM challenges
                    WHERE id=? AND workspace_id=?""",
                (challenge_id, workspace_id),
            ).fetchone()
        if not row:
            from fastapi import HTTPException

            raise HTTPException(404, "Challenge not found.")
        if type(row["ctfd_id"]) is not int or not row["ctfd_url"]:
            raise CTFdError("Only a challenge imported from CTFd can be refreshed.")
        try:
            source = normalize_url(row["ctfd_url"], site=True)
        except CTFdError:
            raise CTFdError("The challenge has an invalid CTFd source mapping.") from None
        return {"id": row["id"], "ctfd_id": row["ctfd_id"], "source_url": source}

    def expire(self):
        for key, item in list(self.previews.items()):
            if item["expires"] <= time.monotonic():
                item["client"].clear_credentials()
                del self.previews[key]

    def preview(self, workspace_id, user, body, mode="import"):
        self.check_owner(workspace_id, user)
        if mode not in {"import", "new"}:
            raise CTFdError("Unsupported CTFd preview mode.")
        selected = self.selected(body)
        if mode == "new" and selected is not None:
            raise CTFdError("Select new challenges after the sync preview is ready.")
        client = None
        with self.preview_slot(user["id"], workspace_id) as cancellation:
            # The service allowance comes before the workspace lifecycle lock.
            # Excess requests therefore leave AnyIO worker threads immediately
            # instead of waiting behind a slow preview for the same workspace.
            with self.workspace_slot(workspace_id):
                try:
                    # The allowance is acquired before factory/plugin code and
                    # therefore before DNS, login, or any remote request.
                    self.check_active(workspace_id, user["id"])
                    client = self.request_client(
                        workspace_id, user, body, allow_saved=mode == "new"
                    )
                    client.cancel_event = cancellation
                    if cancellation.is_set():
                        raise CTFdError("The workspace or user is no longer available.")
                    if mode == "new":
                        existing = self.require_bound_source(workspace_id, client.url)
                    preview = client.preview(
                        selected, metadata_only=True,
                        exclude_ids=set(existing) if mode == "new" else None,
                    )
                    if mode == "new":
                        preview = {
                            **preview,
                            "challenges": [
                                challenge for challenge in preview["challenges"]
                                if challenge["id"] not in existing
                            ],
                        }
                except BaseException:
                    if client is not None:
                        client.clear_credentials()
                    raise
                with self.lock:
                    # This check shares the service lock with account deactivation.
                    # Whichever operation wins either stores then clears the preview,
                    # or observes the inactive user and never retains credentials.
                    try:
                        self.check_active(workspace_id, user["id"])
                    except BaseException:
                        client.clear_credentials()
                        raise
                    self.expire()
                    owned = [key for key, item in self.previews.items() if item["owner"] == user["id"]]
                    for key in owned[:-3]:
                        self.previews.pop(key)["client"].clear_credentials()
                    if len(self.previews) >= 50:
                        client.clear_credentials()
                        raise CTFdError("The preview service is busy. Try again shortly.")
                    preview_id = uuid4().hex
                    self.previews[preview_id] = {
                        "owner": user["id"], "workspace": workspace_id,
                        "client": client, "preview": preview, "mode": mode,
                        "connection_generation": self.saved_connection_generation(client),
                        "expires": time.monotonic() + 900,
                    }
                result = {**preview, "preview_id": preview_id, "auth_type": client.auth_type,
                        "challenges": [{**challenge, "files": [{"name": file["name"]} for file in challenge["files"]]}
                                       for challenge in preview["challenges"]]}
                if mode == "new":
                    result.update(existing_count=len(existing), new_count=len(preview["challenges"]))
                return result

    def consume(self, workspace_id, user, body, *, mode="import"):
        from fastapi import HTTPException
        if body.get("preview_id"):
            with self.lock:
                self.expire()
                item = self.previews.get(body["preview_id"]) if isinstance(body["preview_id"], str) else None
                if not item or item["owner"] != user["id"] or item["workspace"] != workspace_id:
                    raise HTTPException(404, "Preview expired or not found. Preview the site again to authenticate.")
                if item.get("mode", "import") != mode:
                    raise HTTPException(404, "Preview expired or not found. Preview the site again to authenticate.")
                self.previews.pop(body["preview_id"])
            client = item["client"]
            generation = item.get("connection_generation")
            if generation != self.saved_connection_generation(client):
                client.clear_credentials()
                raise HTTPException(
                    404,
                    "Preview expired or not found. Preview the site again to authenticate.",
                )
            return client, item["preview"], generation
        client = self.request_client(
            workspace_id, user, body, allow_saved=mode in {"new", "refresh"}
        )
        return client, None, self.saved_connection_generation(client)

    def start(self, workspace_id, user, body, retry_id=None, *, mode="import",
              target_challenge_id=None):
        from fastapi import HTTPException
        self.check_owner(workspace_id, user)
        # Initialize the additive readable view before handing the job to a
        # background thread; this also avoids opening its migration connection
        # from inside a later write transaction.
        _ = self.layout
        previous = self.get(workspace_id, user, retry_id) if retry_id else None
        if previous:
            mode = previous.get("mode", "import")
            target_challenge_id = previous.get("target_challenge_id")
            if mode == "refresh" and previous.get("refreshed"):
                raise HTTPException(
                    409,
                    "This refresh was already published. Start a new refresh to fetch later changes.",
                )
        if mode not in {"import", "new", "refresh"}:
            raise CTFdError("Unsupported CTFd import mode.")
        target = None
        if mode == "refresh":
            if not target_challenge_id:
                raise CTFdError("Select one CTFd challenge to refresh.")
            target = self.refresh_target(workspace_id, target_challenge_id)
            selected = [target["ctfd_id"]]
            supplied = self.selected(body)
            if supplied is not None and supplied != selected:
                raise CTFdError("The refresh request does not match the selected CTFd challenge.")
        else:
            selected = self.selected(body)
        with self.lock:
            if self.stopping or len(self.workers) >= 2 or any(worker[2] == user["id"] for worker in self.workers.values()):
                raise HTTPException(409, "An import is already running, or the import service is busy.")
            if previous and previous["status"] in {"queued", "running"}:
                raise HTTPException(409, "This import is already running.")
            if previous and not body.get("preview_id") and not body.get("url"):
                if mode == "import" and previous["auth_type"] != "none":
                    raise CTFdError("Preview the site again with authentication before retrying this import.")
                if mode == "import":
                    body = {**body, "url": previous["source_url"], "auth_type": "none"}
            client, preview, connection_generation = self.consume(
                workspace_id, user, body, mode=mode
            )
            if mode == "new":
                try:
                    self.require_bound_source(workspace_id, client.url)
                except BaseException:
                    client.clear_credentials()
                    raise
                if preview is not None:
                    visible_new = {item["id"] for item in preview["challenges"]}
                    if selected is None:
                        selected = sorted(visible_new)
                    elif not set(selected) <= visible_new:
                        client.clear_credentials()
                        raise CTFdError(
                            "The selected challenge was not part of this new-challenge preview."
                        )
                # A direct sync without a preview discovers the current list in
                # the worker. Existing ids are filtered again immediately
                # before insertion, closing the preview/import race.
            elif mode == "refresh" and client.url != target["source_url"]:
                client.clear_credentials()
                raise CTFdError(
                    "The saved CTFd connection does not match this challenge's source site."
                )
            if previous and client.url != previous["source_url"]:
                client.clear_credentials()
                raise CTFdError("Retry must use the same CTFd source site as the original import.")
            job_id = retry_id or uuid4().hex
            lease = self._job_lock(job_id)
            if not lease.try_acquire():
                client.clear_credentials()
                raise HTTPException(409, "This import is already running.")
            try:
                if previous and mode == "refresh":
                    try:
                        clean_generation = self._discard_refresh_generation(
                            job_id, workspace_id, user["id"]
                        )
                    except (OSError, sqlite3.Error):
                        clean_generation = False
                    if not clean_generation:
                        raise HTTPException(
                            409,
                            "The previous refresh generation is still being cleaned up. "
                            "Try again shortly.",
                        )
                self._cancel_marker(job_id).unlink(missing_ok=True)
                with self.db() as db:
                    db.execute("BEGIN IMMEDIATE")
                    active = db.execute(
                        """SELECT 1 FROM workspaces w JOIN users u ON u.id=w.owner_user_id
                           WHERE w.id=? AND w.owner_user_id=? AND u.active=1""",
                        (workspace_id, user["id"]),
                    ).fetchone()
                    if not active:
                        raise CTFdError("The workspace or user is no longer available.")
                    self.require_current_saved_connection(
                        db,
                        workspace_id,
                        user["id"],
                        client,
                        connection_generation,
                    )
                    if mode == "refresh":
                        tables = {
                            row["name"] for row in db.execute(
                                """SELECT name FROM sqlite_master
                                    WHERE type='table' AND name IN
                                          ('solver_jobs','upload_sessions')"""
                            )
                        }
                        if "solver_jobs" in tables and db.execute(
                            """SELECT 1 FROM solver_jobs
                                WHERE owner_user_id=? AND workspace_id=? AND challenge_id=?
                                  AND status IN ('queued','staging','awaiting_credential',
                                      'running','flag_found','writing','cleanup_blocked')
                                LIMIT 1""",
                            (user["id"], workspace_id, target_challenge_id),
                        ).fetchone():
                            raise HTTPException(
                                409,
                                "Stop the active solve before refreshing this challenge.",
                            )
                        if "upload_sessions" in tables and db.execute(
                            """SELECT 1 FROM upload_sessions
                                WHERE owner_user_id=? AND workspace_id=? AND challenge_id=?
                                  AND status='uploading' LIMIT 1""",
                            (user["id"], workspace_id, target_challenge_id),
                        ).fetchone():
                            raise HTTPException(
                                409,
                                "Finish or cancel the active upload before refreshing this challenge.",
                            )
                    active_total = db.execute(
                        "SELECT COUNT(*) FROM ctfd_jobs WHERE status IN ('queued','running')"
                    ).fetchone()[0]
                    active_owner = db.execute(
                        """SELECT 1 FROM ctfd_jobs
                           WHERE owner_user_id=? AND status IN ('queued','running') LIMIT 1""",
                        (user["id"],),
                    ).fetchone()
                    if active_total >= 2 or active_owner:
                        raise HTTPException(
                            409,
                            "An import is already running, or the import service is busy.",
                        )
                    if previous:
                        stored = db.execute(
                            """SELECT selected_ids,status,mode,target_challenge_id,refreshed
                                 FROM ctfd_jobs
                               WHERE id=? AND workspace_id=? AND owner_user_id=?""",
                            (job_id, workspace_id, user["id"]),
                        ).fetchone()
                        if not stored or stored["status"] in {"queued", "running"}:
                            raise HTTPException(409, "This import is already running.")
                        if stored["mode"] != mode or stored["target_challenge_id"] != target_challenge_id:
                            raise CTFdError("The saved import job has an invalid sync scope.")
                        if mode == "refresh" and stored["refreshed"]:
                            raise HTTPException(
                                409,
                                "This refresh was already published. Start a new refresh to fetch later changes.",
                            )
                        selected = json.loads(stored[0]) if stored[0] else None
                        changed = db.execute(
                            """UPDATE ctfd_jobs SET status='queued',cancel_requested=0,
                                 errors='[]',auth_type=?,refreshed=0,updated_at=?
                               WHERE id=? AND status NOT IN ('queued','running')
                                 AND (mode!='refresh' OR refreshed=0)""",
                            (client.auth_type, _now(), job_id),
                        ).rowcount
                        if changed != 1:
                            raise HTTPException(409, "This import is already running.")
                    else:
                        db.execute(
                            """INSERT INTO ctfd_jobs
                               (id,owner_user_id,workspace_id,source_url,auth_type,
                                selected_ids,mode,target_challenge_id,status,created_at,updated_at)
                               VALUES(?,?,?,?,?,?,?,?,'queued',?,?)""",
                            (
                                job_id, user["id"], workspace_id, client.url,
                                client.auth_type,
                                json.dumps(selected) if selected is not None else None,
                                mode, target_challenge_id, _now(), _now(),
                            ),
                        )
            except BaseException:
                client.clear_credentials()
                lease.release()
                raise
            cancel = _ImportCancellation(self._cancel_marker(job_id))
            thread = threading.Thread(target=self.run, args=(job_id, workspace_id, user["id"], client, preview, selected, cancel, lease),
                                      name="ctfd-import-" + job_id[:8], daemon=True)
            self.workers[job_id] = (thread, cancel, user["id"])
            try:
                thread.start()
            except BaseException:
                self.workers.pop(job_id, None)
                client.clear_credentials()
                try:
                    with self.db() as db:
                        db.execute(
                            "UPDATE ctfd_jobs SET status='interrupted',cancel_requested=1,updated_at=? "
                            "WHERE id=? AND status='queued'",
                            (_now(), job_id),
                        )
                finally:
                    lease.release()
                raise
        return {"job": self.get(workspace_id, user, job_id)}

    def path(self, workspace_id, *parts):
        base = self.settings.data_dir / "workspaces"
        path = base
        for part in (workspace_id, *parts):
            if Path(part).name != part or part in {".", ".."}:
                raise CTFdError("Invalid import storage path.")
            path = path / part
            if path.is_symlink():
                raise CTFdError("Invalid import storage path.")
        if not path.resolve().is_relative_to(base.resolve()):
            raise CTFdError("Invalid import storage path.")
        return path

    def alive(self, job_id, workspace_id, owner, cancel):
        if cancel.is_set():
            raise CTFdError("Import interrupted." if self.stopping else "Import cancelled.")
        with self.db() as db:
            valid = db.execute(
                """SELECT 1 FROM ctfd_jobs j
                   JOIN workspaces w ON w.id=j.workspace_id
                   JOIN users u ON u.id=w.owner_user_id
                   WHERE j.id=? AND j.workspace_id=? AND j.owner_user_id=?
                     AND j.status='running' AND j.cancel_requested=0 AND u.active=1""",
                (job_id, workspace_id, owner),
            ).fetchone()
        if not valid:
            cancel.set()
            raise CTFdError("The workspace or user is no longer available.")

    def challenge(self, job_id, workspace_id, owner, source, remote, *, mode="import",
                  target_challenge_id=None):
        connection = remote.get("remote") or ""
        # A CTFd detail response is authoritative for its connection_info
        # field.  An empty value therefore describes an offline challenge,
        # unlike a manually-created challenge where an omitted endpoint still
        # means that the user has not supplied one yet.  Keeping those states
        # distinct prevents the original solver goal's remote-only warning
        # from overriding a CTFd attachment challenge.
        remote_mode = "endpoint" if connection else "none"
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            active = db.execute(
                """SELECT 1 FROM ctfd_jobs j
                   JOIN workspaces w ON w.id=j.workspace_id
                   JOIN users u ON u.id=w.owner_user_id
                   WHERE j.id=? AND j.workspace_id=? AND j.owner_user_id=?
                     AND j.status='running' AND j.cancel_requested=0 AND u.active=1""",
                (job_id, workspace_id, owner),
            ).fetchone()
            if not active:
                raise CTFdError("The workspace or user is no longer available.")
            mapped = db.execute("SELECT * FROM ctfd_job_challenges WHERE job_id=? AND remote_id=?", (job_id, remote["id"])).fetchone()
            if mapped:
                challenge = db.execute(
                    "SELECT workspace_id,ctfd_id,ctfd_url FROM challenges WHERE id=?",
                    (mapped["challenge_id"],),
                ).fetchone()
                try:
                    same_source = challenge is not None and normalize_url(challenge["ctfd_url"], site=True) == source
                except CTFdError:
                    same_source = False
                if (
                    not same_source
                    or challenge["workspace_id"] != workspace_id
                    or challenge["ctfd_id"] != remote["id"]
                ):
                    raise CTFdError("The saved import mapping is invalid.")
                if mode != "refresh":
                    # A resumed partial import fetched fresh challenge detail
                    # before reaching this durable mapping. Refresh only the
                    # CTFd-owned endpoint; local challenge text and solve state
                    # stay intact.
                    db.execute(
                        "UPDATE challenges SET remote=?,remote_mode=?,updated_at=? WHERE id=? AND workspace_id=?",
                        (connection, remote_mode, _now(), mapped["challenge_id"], workspace_id),
                    )
                return mapped["challenge_id"], (
                    False if mode == "refresh" else bool(mapped["skipped"])
                )
            candidates = db.execute("SELECT id,ctfd_url FROM challenges WHERE workspace_id=? AND ctfd_id=?", (workspace_id, remote["id"])).fetchall()
            existing = None
            for candidate in candidates:
                try:
                    if normalize_url(candidate["ctfd_url"], site=True) == source:
                        existing = candidate["id"]
                        break
                except CTFdError:
                    pass
            challenge_id = existing or uuid4().hex
            if mode == "refresh":
                if existing != target_challenge_id:
                    raise CTFdError("The challenge CTFd source mapping changed during refresh.")
                # Metadata and attachments are published together only after
                # every replacement attachment has passed its integrity check.
            elif not existing:
                self.layout.reserve_challenge(
                    db, workspace_id, challenge_id, remote["name"]
                )
                db.execute("INSERT INTO challenges(id,workspace_id,name,category,description,remote,remote_mode,ctfd_id,ctfd_url,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                           (challenge_id, workspace_id, remote["name"], remote["category"], remote["description"], connection, remote_mode, remote["id"], source, _now(), _now()))
            else:
                # Dynamic challenge targets can rotate between imports.  The
                # CTFd-owned field therefore refreshes even when the new value
                # is empty; all user-owned solve state remains untouched.
                db.execute(
                    "UPDATE challenges SET remote=?,remote_mode=?,updated_at=? WHERE id=?",
                    (connection, remote_mode, _now(), challenge_id),
                )
            db.execute("INSERT INTO ctfd_job_challenges VALUES(?,?,?,?)", (job_id, remote["id"], challenge_id, int(bool(existing))))
            db.execute(
                """UPDATE ctfd_jobs
                      SET imported=CASE WHEN mode='refresh' THEN 0 ELSE
                           (SELECT COUNT(*) FROM ctfd_job_challenges WHERE job_id=? AND skipped=0) END,
                          skipped=CASE WHEN mode='refresh' THEN 0 ELSE
                           (SELECT COUNT(*) FROM ctfd_job_challenges WHERE job_id=? AND skipped=1) END,
                          updated_at=? WHERE id=?""",
                (job_id, job_id, _now(), job_id),
            )
        self.layout.challenge_path(workspace_id, challenge_id, create=True)
        return challenge_id, False if mode == "refresh" else bool(existing)

    def file(self, job_id, challenge_id, remote_id, index, source):
        parsed = urlsplit(source["url"])
        identity = hashlib.sha256(urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", "")).encode()).hexdigest()
        with self.db() as db:
            row = db.execute("SELECT * FROM ctfd_job_files WHERE job_id=? AND remote_id=? AND file_index=?", (job_id, remote_id, index)).fetchone()
            if row:
                if row["url_hash"] != identity or row["original_name"] != source["name"]:
                    raise CTFdError("The remote attachment list changed. Create a new import after reviewing the challenge.")
                return dict(row)
            file_id = uuid4().hex
            workspace_id = db.execute(
                "SELECT workspace_id FROM challenges WHERE id=?", (challenge_id,)
            ).fetchone()[0]
            self.layout.reserve_attachment(
                db, workspace_id, challenge_id, file_id, source["name"]
            )
            db.execute("INSERT INTO ctfd_job_files(id,job_id,challenge_id,remote_id,file_index,original_name,url_hash) VALUES(?,?,?,?,?,?,?)",
                       (file_id, job_id, challenge_id, remote_id, index, source["name"], identity))
            return dict(db.execute("SELECT * FROM ctfd_job_files WHERE id=?", (file_id,)).fetchone())

    def progress(self, job_id, file_id, name, size, total, validator):
        with self.db() as db:
            db.execute("UPDATE ctfd_job_files SET bytes=?,total=?,validator=? WHERE id=?", (size, total, validator, file_id))
            db.execute("UPDATE ctfd_jobs SET downloaded_bytes=(SELECT COALESCE(SUM(bytes),0) FROM ctfd_job_files WHERE job_id=?),current_file=?,total_bytes=?,updated_at=? WHERE id=?", (job_id, name, total, _now(), job_id))

    @staticmethod
    def reservation(file_id):
        return "ctfd:" + file_id

    def release_job_reservations(self, job_id):
        with self.db() as db:
            keys = [self.reservation(row[0]) for row in db.execute(
                "SELECT id FROM ctfd_job_files WHERE job_id=?", (job_id,)
            )]
        self.budget.release_many(keys)

    def finalize(self, job_id, workspace_id, file, partial, destination, cancel,
                 *, publish=True):
        candidate = destination if destination.exists() else partial
        if candidate.is_symlink() or not candidate.is_file() or candidate.stat().st_size != file["bytes"]:
            raise CTFdError("The saved attachment is incomplete. Retry the download.")
        digest_state = hashlib.sha256()
        with candidate.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                if cancel.is_set():
                    raise CTFdError("Import cancelled.")
                digest_state.update(chunk)
        digest = digest_state.hexdigest()
        if digest != file["sha256"]:
            raise CTFdError("The saved attachment failed its integrity check. Retry the download.")
        if cancel.is_set():
            raise CTFdError("Import cancelled.")
        destination.parent.mkdir(parents=True, exist_ok=True)
        if candidate != destination:
            partial.replace(destination)
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            active = db.execute(
                """SELECT 1 FROM ctfd_jobs j JOIN ctfd_job_files f ON f.job_id=j.id
                   WHERE j.id=? AND j.workspace_id=? AND j.status='running'
                     AND j.cancel_requested=0 AND f.id=? AND f.challenge_id=?""",
                (job_id, workspace_id, file["id"], file["challenge_id"]),
            ).fetchone()
            if not active:
                raise CTFdError("Import cancelled.")
            if publish:
                db.execute("INSERT OR IGNORE INTO attachments(id,workspace_id,challenge_id,original_name,stored_name,size,created_at) VALUES(?,?,?,?,?,?,?)",
                           (file["id"], workspace_id, file["challenge_id"], file["original_name"], file["id"], file["bytes"], _now()))
                attachment = db.execute(
                    "SELECT * FROM attachments WHERE id=?", (file["id"],)
                ).fetchone()
                self.layout.ensure_attachment_view(
                    db, workspace_id, file["challenge_id"], attachment,
                    view_wins=False,
                )
                db.execute(
                    """INSERT OR IGNORE INTO ctfd_managed_attachments
                       (attachment_id,workspace_id,challenge_id,source_url,remote_id,
                        file_index,url_hash,sha256)
                       SELECT f.id,?,?,j.source_url,f.remote_id,f.file_index,f.url_hash,f.sha256
                         FROM ctfd_job_files f JOIN ctfd_jobs j ON j.id=f.job_id
                        WHERE f.id=? AND f.job_id=?""",
                    (workspace_id, file["challenge_id"], file["id"], job_id),
                )
            db.execute("UPDATE ctfd_job_files SET status='done' WHERE id=?", (file["id"],))
            db.execute("UPDATE ctfd_jobs SET attachments=(SELECT COUNT(*) FROM ctfd_job_files WHERE job_id=? AND status='done'),updated_at=? WHERE id=?", (job_id, _now(), job_id))

    @staticmethod
    def _open_verified_regular(path, expected_size, expected_digest):
        """Open and hash one no-follow file; the caller owns the returned fd."""

        if (
            type(expected_size) is not int
            or expected_size < 0
            or not isinstance(expected_digest, str)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_digest)
        ):
            raise CTFdError("The staged attachment metadata is invalid.")
        descriptor = None
        digest = hashlib.sha256()
        total = 0
        try:
            descriptor = os.open(
                path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            )
            before = os.fstat(descriptor)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_size != expected_size
                or before.st_nlink != 1
            ):
                raise CTFdError("The staged attachment is not an independent regular file.")
            while True:
                chunk = os.read(descriptor, 4 * 1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                digest.update(chunk)
            after = os.fstat(descriptor)
            if (
                total != expected_size
                or after.st_dev != before.st_dev
                or after.st_ino != before.st_ino
                or after.st_size != before.st_size
                or after.st_mtime_ns != before.st_mtime_ns
                or after.st_nlink != before.st_nlink
                or not secrets.compare_digest(digest.hexdigest(), expected_digest)
            ):
                raise CTFdError("The staged attachment failed its publication check.")
            return descriptor, after
        except OSError as exc:
            if descriptor is not None:
                os.close(descriptor)
            raise CTFdError("The staged attachment could not be verified.") from exc
        except BaseException:
            if descriptor is not None:
                os.close(descriptor)
            raise

    @staticmethod
    def _descriptor_still_at(descriptor, path, expected):
        try:
            current = os.fstat(descriptor)
            linked = os.lstat(path)
        except OSError:
            return False
        return bool(
            stat.S_ISREG(current.st_mode)
            and stat.S_ISREG(linked.st_mode)
            and current.st_nlink == linked.st_nlink == 1
            and current.st_dev == linked.st_dev == expected.st_dev
            and current.st_ino == linked.st_ino == expected.st_ino
            and current.st_size == linked.st_size == expected.st_size
            and current.st_mtime_ns == linked.st_mtime_ns == expected.st_mtime_ns
        )

    def _remove_job_staging(self, workspace_id, job_id):
        """Remove only the directory owned by one importer job."""

        try:
            parent = self.path(workspace_id, "ctfd_jobs")
            if Path(job_id).name != job_id or job_id in {".", ".."}:
                return False
            root = parent / job_id
            if root.is_symlink():
                return False
            if root.exists():
                shutil.rmtree(root)
            return not root.exists()
        except (CTFdError, OSError):
            return False

    def _discard_refresh_generation(self, job_id, workspace_id, owner):
        """Delete one unpublished refresh generation without touching live files."""

        with self.db() as db:
            job = db.execute(
                """SELECT mode,refreshed FROM ctfd_jobs
                    WHERE id=? AND workspace_id=? AND owner_user_id=?""",
                (job_id, workspace_id, owner),
            ).fetchone()
            files = [
                dict(row)
                for row in db.execute(
                    """SELECT id,challenge_id FROM ctfd_job_files
                        WHERE job_id=? ORDER BY id""",
                    (job_id,),
                )
            ]
            referenced = {
                row[0]
                for row in db.execute(
                    """SELECT a.id FROM attachments a
                        JOIN ctfd_job_files f ON f.id=a.id
                        WHERE f.job_id=?""",
                    (job_id,),
                )
            }
        if not job or job["mode"] != "refresh":
            return True
        if job["refreshed"]:
            return self._remove_job_staging(workspace_id, job_id)
        if referenced:
            return False

        # A failed publish may already have moved a subset beside the live
        # attachments. IDs are job-generated and are deleted only while no
        # attachment row references them.
        for file in files:
            try:
                parent = self.path(
                    workspace_id,
                    "challenges",
                    file["challenge_id"],
                    "attachments",
                )
                if not re.fullmatch(r"[0-9a-f]{32}", file["id"]):
                    return False
                target = parent / file["id"]
                if os.path.lexists(target):
                    details = os.lstat(target)
                    if stat.S_ISDIR(details.st_mode):
                        return False
                    target.unlink()
            except (CTFdError, OSError):
                return False
        if not self._remove_job_staging(workspace_id, job_id):
            return False

        self.release_job_reservations(job_id)
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            current = db.execute(
                """SELECT mode,refreshed FROM ctfd_jobs
                    WHERE id=? AND workspace_id=? AND owner_user_id=?""",
                (job_id, workspace_id, owner),
            ).fetchone()
            if not current or current["mode"] != "refresh":
                return True
            if current["refreshed"] or db.execute(
                """SELECT 1 FROM attachments a JOIN ctfd_job_files f ON f.id=a.id
                    WHERE f.job_id=? LIMIT 1""",
                (job_id,),
            ).fetchone():
                return False
            for file in files:
                self.layout.forget(db, "attachment", file["id"])
            db.execute("DELETE FROM ctfd_job_files WHERE job_id=?", (job_id,))
            db.execute(
                """UPDATE ctfd_jobs SET attachments=0,downloaded_bytes=0,
                     current_file='',total_bytes=NULL,updated_at=? WHERE id=?""",
                (_now(), job_id),
            )
        return True

    def cleanup_terminal_refresh_staging(self):
        """Retry crash-safe cleanup for terminal unpublished refresh jobs."""

        with self.db() as db:
            jobs = db.execute(
                """SELECT j.id,j.workspace_id,j.owner_user_id,
                          EXISTS(SELECT 1 FROM ctfd_job_files f WHERE f.job_id=j.id)
                            AS has_files
                     FROM ctfd_jobs j
                    WHERE j.mode='refresh' AND j.refreshed=0
                      AND j.status NOT IN ('queued','running')"""
            ).fetchall()
        cleaned = 0
        for job in jobs:
            try:
                staging = self.path(
                    job["workspace_id"], "ctfd_jobs", job["id"]
                )
            except CTFdError:
                continue
            if not job["has_files"] and not os.path.lexists(staging):
                continue
            lease = self._job_lock(job["id"])
            if not lease.try_acquire():
                continue
            try:
                cleaned += int(
                    self._discard_refresh_generation(
                        job["id"], job["workspace_id"], job["owner_user_id"]
                    )
                )
            finally:
                lease.release()
        return cleaned

    def publish_refresh(self, job_id, workspace_id, owner, source, remote,
                        challenge_id, cancel):
        """Atomically publish refreshed metadata and replacement CTFd files."""

        if cancel.is_set():
            raise CTFdError("Import cancelled.")
        connection = remote.get("remote") or ""
        remote_mode = "endpoint" if connection else "none"
        with self.db() as db:
            staged = [
                dict(row)
                for row in db.execute(
                    """SELECT * FROM ctfd_job_files
                        WHERE job_id=? AND challenge_id=? AND remote_id=?
                        ORDER BY file_index""",
                    (job_id, challenge_id, remote["id"]),
                )
            ]
        if len(staged) != len(remote["files"]) or any(
            row["status"] != "done" for row in staged
        ):
            raise CTFdError("The refreshed attachment set is incomplete.")

        opened = []
        attachment_root = self.path(
            workspace_id, "challenges", challenge_id, "attachments"
        )
        attachment_root.mkdir(parents=True, exist_ok=True)
        try:
            for row in staged:
                ready = self.path(
                    workspace_id, "ctfd_jobs", job_id, "ready", row["id"]
                )
                destination = attachment_root / row["id"]
                if os.path.lexists(destination):
                    raise CTFdError("The refreshed attachment destination already exists.")
                try:
                    os.replace(ready, destination)
                except OSError as exc:
                    raise CTFdError("The refreshed attachment could not be staged.") from exc
                descriptor, signature = self._open_verified_regular(
                    destination, row["bytes"], row["sha256"]
                )
                opened.append((descriptor, destination, signature))
            if hasattr(os, "O_DIRECTORY"):
                directory_fd = os.open(attachment_root, os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)

            old_files = []
            with self.db() as db:
                db.execute("BEGIN IMMEDIATE")
                active = db.execute(
                    """SELECT c.ctfd_id,c.ctfd_url
                         FROM ctfd_jobs j
                         JOIN workspaces w
                           ON w.id=j.workspace_id AND w.owner_user_id=j.owner_user_id
                         JOIN users u ON u.id=j.owner_user_id
                         JOIN challenges c ON c.id=j.target_challenge_id
                                               AND c.workspace_id=j.workspace_id
                        WHERE j.id=? AND j.workspace_id=? AND j.owner_user_id=?
                          AND j.mode='refresh' AND j.target_challenge_id=?
                          AND j.refreshed=0 AND j.status='running'
                          AND j.cancel_requested=0 AND u.active=1""",
                    (job_id, workspace_id, owner, challenge_id),
                ).fetchone()
                try:
                    same_source = (
                        active is not None
                        and normalize_url(active["ctfd_url"], site=True) == source
                    )
                except CTFdError:
                    same_source = False
                if not same_source or active["ctfd_id"] != remote["id"]:
                    raise CTFdError(
                        "The challenge CTFd source mapping changed during refresh."
                    )

                current_staged = [
                    dict(row)
                    for row in db.execute(
                        """SELECT * FROM ctfd_job_files
                            WHERE job_id=? AND challenge_id=? AND remote_id=?
                            ORDER BY file_index""",
                        (job_id, challenge_id, remote["id"]),
                    )
                ]
                compared_fields = (
                    "id", "challenge_id", "remote_id", "file_index",
                    "original_name", "url_hash", "status", "bytes", "sha256",
                )
                if [
                    tuple(row[field] for field in compared_fields)
                    for row in current_staged
                ] != [
                    tuple(row[field] for field in compared_fields)
                    for row in staged
                ] or any(
                    not self._descriptor_still_at(descriptor, path, signature)
                    for descriptor, path, signature in opened
                ):
                    raise CTFdError(
                        "The refreshed attachment generation changed before publication."
                    )

                tables = {
                    row["name"]
                    for row in db.execute(
                        """SELECT name FROM sqlite_master WHERE type='table'
                            AND name IN ('solver_jobs','upload_sessions')"""
                    )
                }
                if "solver_jobs" in tables and db.execute(
                    """SELECT 1 FROM solver_jobs
                        WHERE owner_user_id=? AND workspace_id=? AND challenge_id=?
                          AND status IN ('queued','staging','awaiting_credential',
                              'running','flag_found','writing','cleanup_blocked')
                        LIMIT 1""",
                    (owner, workspace_id, challenge_id),
                ).fetchone():
                    raise CTFdError(
                        "A solve started before the CTFd refresh was published."
                    )
                if "upload_sessions" in tables and db.execute(
                    """SELECT 1 FROM upload_sessions
                        WHERE owner_user_id=? AND workspace_id=? AND challenge_id=?
                          AND status='uploading' LIMIT 1""",
                    (owner, workspace_id, challenge_id),
                ).fetchone():
                    raise CTFdError(
                        "An attachment upload started before the CTFd refresh was published."
                    )

                changed = db.execute(
                    """UPDATE ctfd_jobs SET imported=0,skipped=0,refreshed=1,
                         attachments=?,updated_at=?
                       WHERE id=? AND mode='refresh' AND refreshed=0
                         AND status='running' AND cancel_requested=0""",
                    (len(staged), _now(), job_id),
                ).rowcount
                if changed != 1:
                    raise CTFdError("The refresh publication state changed.")

            # Also cover an attachment published concurrently by an older
            # rolling-deployment process after this service initialized.
                db.execute(
                    """INSERT OR IGNORE INTO ctfd_managed_attachments
                       (attachment_id,workspace_id,challenge_id,source_url,remote_id,
                        file_index,url_hash,sha256)
                       SELECT a.id,a.workspace_id,a.challenge_id,j.source_url,f.remote_id,
                              f.file_index,f.url_hash,f.sha256
                         FROM ctfd_job_files f
                         JOIN ctfd_jobs j ON j.id=f.job_id
                         JOIN attachments a ON a.id=f.id
                        WHERE f.status='done' AND a.workspace_id=? AND a.challenge_id=?
                          AND j.source_url=? AND f.remote_id=?""",
                    (workspace_id, challenge_id, source, remote["id"]),
                )
                old_files = [dict(row) for row in db.execute(
                    """SELECT m.attachment_id,a.stored_name,a.original_name,
                              m.file_index,r.name AS readable_name
                         FROM ctfd_managed_attachments m
                         JOIN attachments a ON a.id=m.attachment_id
                         LEFT JOIN readable_storage_paths r
                           ON r.kind='attachment' AND r.entity_id=m.attachment_id
                        WHERE m.workspace_id=? AND m.challenge_id=?
                          AND m.source_url=? AND m.remote_id=?""",
                    (workspace_id, challenge_id, source, remote["id"]),
                ).fetchall()]
                # Commit the stable readable-name handoff with the attachment
                # generation. Startup can finish it if the process stops before
                # the post-commit filesystem reconciliation runs.
                self.layout.plan_refresh_views(
                    db, workspace_id, challenge_id, old_files, staged
                )
                for old_file in old_files:
                    self.layout.plan_delete(
                        db, "attachment", old_file["attachment_id"], workspace_id,
                        challenge_id=challenge_id,
                        stored_name=old_file["stored_name"],
                        readable_name=old_file["readable_name"] or "",
                    )
            # Removing only rows carrying importer provenance keeps manual
            # uploads intact. The whole transaction rolls back if a new row
            # cannot be published.
                db.execute(
                    """UPDATE challenges
                          SET name=?,category=?,description=?,remote=?,remote_mode=?,updated_at=?
                        WHERE id=? AND workspace_id=?""",
                    (
                        remote["name"], remote["category"], remote["description"],
                        connection, remote_mode, _now(), challenge_id, workspace_id,
                    ),
                )
                db.executemany(
                    "DELETE FROM attachments WHERE id=? AND workspace_id=? AND challenge_id=?",
                    (
                        (row["attachment_id"], workspace_id, challenge_id)
                        for row in old_files
                    ),
                )
                for row in staged:
                    db.execute(
                        """INSERT INTO attachments
                           (id,workspace_id,challenge_id,original_name,stored_name,size,created_at)
                           VALUES(?,?,?,?,?,?,?)""",
                        (
                            row["id"], workspace_id, challenge_id,
                            row["original_name"], row["id"], row["bytes"], _now(),
                        ),
                    )
                    db.execute(
                        """INSERT INTO ctfd_managed_attachments
                           (attachment_id,workspace_id,challenge_id,source_url,remote_id,
                            file_index,url_hash,sha256) VALUES(?,?,?,?,?,?,?,?)""",
                        (
                            row["id"], workspace_id, challenge_id, source,
                            row["remote_id"], row["file_index"], row["url_hash"],
                            row["sha256"],
                        ),
                    )
        finally:
            for descriptor, _path, _signature in opened:
                os.close(descriptor)

        self.layout.reconcile_refresh_views(
            workspace_id, challenge_id, old_files, staged
        )

        new_ids = {row["id"] for row in staged}
        # Database publication is the commit point. Never unlink an ID reused
        # by this generation, even if a corrupted/stale retry reached here.
        for row in old_files:
            if row["attachment_id"] in new_ids:
                continue
            try:
                path = self.path(
                    workspace_id,
                    "challenges",
                    challenge_id,
                    "attachments",
                    row["stored_name"],
                )
                if not path.is_symlink():
                    path.unlink(missing_ok=True)
            except (CTFdError, OSError):
                pass
        self.layout.finish_deletions()
        self._remove_job_staging(workspace_id, job_id)

    def run(self, job_id, workspace_id, owner, client, preview, selected, cancel, lease=None):
        lease = lease or self._job_lock(job_id)
        try:
            while not lease.try_acquire():
                if cancel.is_set():
                    client.clear_credentials()
                    return
                time.sleep(.02)
            self._run_leased(
                job_id, workspace_id, owner, client, preview, selected, cancel,
            )
        except BaseException:
            client.clear_credentials()
            with self.lock:
                self.workers.pop(job_id, None)
            raise
        finally:
            lease.release()

    def _run_leased(self, job_id, workspace_id, owner, client, preview, selected, cancel):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            claimed = db.execute(
                """UPDATE ctfd_jobs SET status='running',updated_at=?
                   WHERE id=? AND workspace_id=? AND owner_user_id=?
                     AND status='queued' AND cancel_requested=0
                     AND EXISTS (
                       SELECT 1 FROM workspaces w JOIN users u ON u.id=w.owner_user_id
                       WHERE w.id=ctfd_jobs.workspace_id
                         AND w.owner_user_id=ctfd_jobs.owner_user_id AND u.active=1
                     )""",
                (_now(), job_id, workspace_id, owner),
            ).rowcount
            scope = db.execute(
                "SELECT mode,target_challenge_id FROM ctfd_jobs WHERE id=?",
                (job_id,),
            ).fetchone()
        if claimed != 1:
            client.clear_credentials()
            cleaned = True
            if scope is not None and scope["mode"] == "refresh":
                try:
                    cleaned = self._discard_refresh_generation(
                        job_id, workspace_id, owner
                    )
                except (OSError, sqlite3.Error):
                    cleaned = False
            if cleaned:
                self.release_job_reservations(job_id)
            with self.lock:
                self.workers.pop(job_id, None)
            return
        errors = []
        status = "failed"
        mode = scope["mode"] if scope else "import"
        target_challenge_id = scope["target_challenge_id"] if scope else None
        try:
            client.cancel_event = cancel
            self.alive(job_id, workspace_id, owner, cancel)
            bound = self.require_bound_source(workspace_id, client.url) if mode == "new" else {}
            # A partial new-only job already owns the challenges it inserted.
            # Keep those IDs in the retry so failed attachments resume; only
            # challenges owned outside this job are idempotent exclusions.
            owned_remote_ids = set()
            if mode == "new":
                with self.db() as db:
                    owned_remote_ids = {
                        row[0]
                        for row in db.execute(
                            """SELECT remote_id FROM ctfd_job_challenges
                                WHERE job_id=? AND skipped=0""",
                            (job_id,),
                        )
                    }
            excluded_bound = set(bound) - owned_remote_ids
            preview = (
                client.preview(
                    selected,
                    exclude_ids=excluded_bound if mode == "new" else None,
                )
                if not preview or preview.get("details_pending") else preview
            )
            errors.extend(error for error in preview["errors"] if selected is None or error.get("challenge_id") is None or error.get("challenge_id") in selected)
            remote_challenges = [item for item in preview["challenges"] if selected is None or item["id"] in selected]
            if mode == "new":
                remote_challenges = [
                    item for item in remote_challenges
                    if item["id"] not in excluded_bound
                ]
            required = set(selected or ())
            if mode == "new":
                # A direct new-only sync may have stored no explicit selection.
                # Its retry must still account for challenges this same job
                # already created; otherwise a temporarily hidden upstream row
                # could turn an unfinished attachment into a false success.
                required.update(owned_remote_ids)
            missing = required - {item["id"] for item in remote_challenges}
            if missing:
                # IDs that became imported by another job between preview and
                # worker claim are an idempotent no-op for a new-only sync.
                if mode != "new" or not missing <= excluded_bound:
                    errors.append({"challenge_id": None, "message": "Some selected challenges are no longer visible. Preview again before retrying."})
            for remote in remote_challenges:
                self.alive(job_id, workspace_id, owner, cancel)
                challenge_id, skipped = self.challenge(
                    job_id, workspace_id, owner, client.url, remote,
                    mode=mode, target_challenge_id=target_challenge_id,
                )
                if skipped:
                    continue
                for index, source in enumerate(remote["files"]):
                    self.alive(job_id, workspace_id, owner, cancel)
                    file = None
                    try:
                        file = self.file(job_id, challenge_id, remote["id"], index, source)
                        if file["status"] == "done":
                            continue
                        partial = self.path(workspace_id, "ctfd_jobs", job_id, "partials", file["id"] + ".partial")
                        destination = (
                            self.path(
                                workspace_id,
                                "ctfd_jobs",
                                job_id,
                                "ready",
                                file["id"],
                            )
                            if mode == "refresh"
                            else self.path(
                                workspace_id,
                                "challenges",
                                challenge_id,
                                "attachments",
                                file["id"],
                            )
                        )
                        partial.parent.mkdir(parents=True, exist_ok=True)
                        if file["status"] == "ready":
                            try:
                                self.finalize(
                                    job_id, workspace_id, file, partial, destination,
                                    cancel, publish=mode != "refresh",
                                )
                                continue
                            except CTFdError:
                                if cancel.is_set():
                                    raise
                                # These unpublished artifacts belong exclusively
                                # to this job. Corrupt crash leftovers restart.
                                for artifact in (partial, destination):
                                    if artifact.is_symlink():
                                        raise CTFdError("Invalid import storage path.")
                                    artifact.unlink(missing_ok=True)
                                self.budget.release(self.reservation(file["id"]))
                                with self.db() as db:
                                    db.execute("UPDATE ctfd_job_files SET status='pending',bytes=0,total=NULL,validator='',sha256='' WHERE id=?", (file["id"],))
                                file.update(status="pending", bytes=0, total=None, validator="", sha256="")
                        if file["status"] != "ready":
                            def progress(size, total, validator):
                                self.alive(job_id, workspace_id, owner, cancel)
                                self.progress(job_id, file["id"], file["original_name"], size, total, validator)
                            result = client.download_to(
                                source["url"], partial, validator=file["validator"],
                                progress=progress, cancel=cancel,
                                storage_budget=self.budget,
                                storage_reservation=(
                                    self.reservation(file["id"]), owner,
                                    workspace_id, challenge_id,
                                ),
                            )
                            file.update(result)
                            with self.db() as db:
                                db.execute("UPDATE ctfd_job_files SET status='ready',bytes=?,total=?,validator=?,sha256=? WHERE id=?", (result["bytes"], result["total"], result["validator"], result["sha256"], file["id"]))
                        self.alive(job_id, workspace_id, owner, cancel)
                        self.finalize(
                            job_id, workspace_id, file, partial, destination,
                            cancel, publish=mode != "refresh",
                        )
                    except (CTFdError, OSError) as exc:
                        # Refresh artifacts remain private until one atomic
                        # publication. Keep their reservation until the whole
                        # generation is removed; a failed cleanup must not turn
                        # a multi-gigabyte partial into unaccounted reusable
                        # capacity.
                        if file is not None and mode != "refresh":
                            self.budget.release(self.reservation(file["id"]))
                        if cancel.is_set():
                            raise
                        message = str(exc) if isinstance(exc, CTFdError) else "The attachment could not be saved on the data volume. Check available space and permissions."
                        errors.append({"challenge_id": remote["id"], "file": source["name"], "message": message})
                if mode == "refresh" and not errors:
                    self.publish_refresh(
                        job_id, workspace_id, owner, client.url, remote,
                        challenge_id, cancel,
                    )
            status = "partial" if errors else "completed"
        except (CTFdError, OSError, sqlite3.Error) as exc:
            message = str(exc) if isinstance(exc, CTFdError) else "The import could not access its local storage. Check available space and permissions."
            errors.append({"challenge_id": None, "message": message})
        except Exception:
            errors.append({"challenge_id": None, "message": "The import could not complete. Preview the site again and retry."})
        finally:
            if cancel.is_set():
                status = "interrupted" if self.stopping else "cancelled"
            client.clear_credentials()
            cleaned = mode != "refresh"
            if mode == "refresh":
                try:
                    with self.db() as db:
                        published = db.execute(
                            "SELECT refreshed FROM ctfd_jobs WHERE id=?",
                            (job_id,),
                        ).fetchone()
                    cleaned = self._discard_refresh_generation(
                        job_id, workspace_id, owner
                    )
                except (OSError, sqlite3.Error):
                    published = None
                    cleaned = False
                if published is not None and not published["refreshed"] and not cleaned:
                    errors.append(
                        {
                            "challenge_id": None,
                            "message": "The unpublished refresh files are still being cleaned up.",
                        }
                    )
                    if status == "completed":
                        status = "partial"
            if cleaned:
                self.release_job_reservations(job_id)
            with self.lock:
                try:
                    self.update(job_id, status=status, errors=json.dumps(errors[:300], ensure_ascii=False), current_file="", total_bytes=None)
                finally:
                    self.workers.pop(job_id, None)

    def _cancel_scope(self, condition, parameters, terminal_status, wait_seconds):
        with self.db() as db:
            db.execute("BEGIN IMMEDIATE")
            ids = [
                row["id"] for row in db.execute(
                    "SELECT id FROM ctfd_jobs WHERE " + condition
                    + " AND status IN ('queued','running')",
                    parameters,
                )
            ]
            db.execute(
                "UPDATE ctfd_jobs SET cancel_requested=1,updated_at=? WHERE "
                + condition + " AND status IN ('queued','running')",
                (_now(), *parameters),
            )
        with self.lock:
            local = [self.workers.get(job_id) for job_id in ids]
            for worker in local:
                if worker:
                    try:
                        worker[1].set()
                    except OSError:
                        pass
        for job_id in ids:
            try:
                self._signal_job(job_id)
            except OSError:
                pass

        deadline = time.monotonic() + max(0.0, float(wait_seconds))
        stopped = True
        for job_id in ids:
            lease = self._job_lock(job_id)
            while not lease.try_acquire():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    stopped = False
                    break
                time.sleep(min(.02, remaining))
            if not lease.locked:
                continue
            try:
                scope = None
                with self.db() as db:
                    db.execute("BEGIN IMMEDIATE")
                    db.execute(
                        """UPDATE ctfd_jobs SET status=?,current_file='',updated_at=?
                           WHERE id=? AND status IN ('queued','running')
                             AND cancel_requested=1""",
                        (terminal_status, _now(), job_id),
                    )
                    scope = db.execute(
                        """SELECT mode,workspace_id,owner_user_id
                             FROM ctfd_jobs WHERE id=?""",
                        (job_id,),
                    ).fetchone()
                cleaned = True
                if scope is not None and scope["mode"] == "refresh":
                    try:
                        cleaned = self._discard_refresh_generation(
                            job_id, scope["workspace_id"], scope["owner_user_id"]
                        )
                    except (OSError, sqlite3.Error):
                        cleaned = False
                if cleaned:
                    self.release_job_reservations(job_id)
            finally:
                lease.release()
        return stopped

    def cancel(self, workspace_id, user, job_id):
        self.get(workspace_id, user, job_id)
        self._cancel_scope(
            "id=? AND workspace_id=? AND owner_user_id=?",
            (job_id, workspace_id, user["id"]),
            "cancelled",
            0,
        )
        return {"job": self.get(workspace_id, user, job_id)}

    def _cancel_preview_scope(self, *, owner_user_id=None, workspace_id=None, wait_seconds=12):
        """Signal an in-flight preview and wait for its cross-process lease."""

        if (owner_user_id is None) == (workspace_id is None):
            raise ValueError("exactly one preview cancellation scope is required")
        with self.preview_slot_lock:
            for owner, (active_workspace, cancellation) in list(self.preview_cancellations.items()):
                if owner_user_id == owner or workspace_id == active_workspace:
                    try:
                        cancellation.set()
                    except OSError:
                        pass
        if owner_user_id is not None:
            marker = self._preview_cancel_marker(owner_user_id)
            lease = self._preview_lock(owner_user_id)
        else:
            marker = self._workspace_preview_cancel_marker(workspace_id)
            lease = self._workspace_preview_lock(workspace_id)
        try:
            _ImportCancellation(marker).set()
        except OSError:
            pass
        deadline = time.monotonic() + max(0.0, float(wait_seconds))
        while not lease.try_acquire():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(.02, remaining))
        lease.release()
        return True

    def shutdown(self):
        self.janitor_stop.set()
        with self.lock:
            self.stopping = True
            worker_items = list(self.workers.items())
            for _, (_, cancel, _) in worker_items:
                cancel.set()
            for item in self.previews.values():
                item["client"].clear_credentials()
            self.previews.clear()
        with self.preview_slot_lock:
            for _, cancellation in self.preview_cancellations.values():
                try:
                    cancellation.set()
                except OSError:
                    pass
        ids = [job_id for job_id, _ in worker_items]
        if ids:
            with self.db() as db:
                db.execute("BEGIN IMMEDIATE")
                db.executemany(
                    "UPDATE ctfd_jobs SET cancel_requested=1,updated_at=? "
                    "WHERE id=? AND status IN ('queued','running')",
                    ((_now(), job_id) for job_id in ids),
                )
        deadline = time.monotonic() + 12
        for _, (thread, _, _) in worker_items:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            thread.join(timeout=remaining)
        self.janitor.join(timeout=1)

    def cancel_workspace(self, workspace_id):
        """Stop every cross-process writer before workspace or challenge deletion."""
        preview_stopped = self._cancel_preview_scope(workspace_id=workspace_id)
        with self.lock:
            for key, item in list(self.previews.items()):
                if item["workspace"] == workspace_id:
                    item["client"].clear_credentials()
                    del self.previews[key]
        imports_stopped = self._cancel_scope(
            "workspace_id=?", (workspace_id,), "cancelled", 12,
        )
        return preview_stopped and imports_stopped

    def cancel_owner(self, owner_user_id):
        """Cancel imports and clear previews when an administrator disables a user."""
        preview_stopped = self._cancel_preview_scope(owner_user_id=owner_user_id)
        with self.lock:
            for key, item in list(self.previews.items()):
                if item["owner"] == owner_user_id:
                    item["client"].clear_credentials()
                    del self.previews[key]
        imports_stopped = self._cancel_scope(
            "owner_user_id=?", (owner_user_id,), "interrupted", 12,
        )
        return preview_stopped and imports_stopped


def register_ctfd(app, require_auth, settings):
    from fastapi import Depends, HTTPException

    jobs = ImportJobs(app, settings)
    app.state.ctfd_jobs = jobs
    app.router.add_event_handler("shutdown", jobs.shutdown)

    def call(operation, *args, **kwargs):
        try:
            return operation(*args, **kwargs)
        except CTFdError as exc:
            raise HTTPException(422, str(exc)) from None

    @app.post("/api/workspaces/{workspace_id}/ctfd/preview")
    def preview_ctfd(workspace_id: str, body: dict, user=Depends(require_auth)):
        return call(jobs.preview, workspace_id, user, body)

    @app.post("/api/workspaces/{workspace_id}/ctfd/sync/preview")
    def preview_new_ctfd(workspace_id: str, body: dict, user=Depends(require_auth)):
        """List only challenges not yet mapped from the saved source."""

        return call(jobs.preview, workspace_id, user, body, "new")

    @app.post("/api/workspaces/{workspace_id}/ctfd/import", status_code=202)
    def import_ctfd(workspace_id: str, body: dict, user=Depends(require_auth)):
        with jobs.workspace_slot(workspace_id):
            return call(jobs.start, workspace_id, user, body)

    @app.post("/api/workspaces/{workspace_id}/ctfd/sync", status_code=202)
    def sync_new_ctfd(workspace_id: str, body: dict, user=Depends(require_auth)):
        with jobs.workspace_slot(workspace_id):
            return call(jobs.start, workspace_id, user, body, None, mode="new")

    @app.post(
        "/api/workspaces/{workspace_id}/challenges/{challenge_id}/ctfd/refresh",
        status_code=202,
    )
    def refresh_ctfd_challenge(
        workspace_id: str, challenge_id: str, body: dict,
        user=Depends(require_auth),
    ):
        with jobs.workspace_slot(workspace_id):
            return call(
                jobs.start, workspace_id, user, body, None,
                mode="refresh", target_challenge_id=challenge_id,
            )

    @app.get("/api/workspaces/{workspace_id}/ctfd/jobs")
    def list_ctfd_jobs(workspace_id: str, user=Depends(require_auth)):
        jobs.check_owner(workspace_id, user)
        with jobs.db() as db:
            ids = db.execute("SELECT id FROM ctfd_jobs WHERE workspace_id=? AND owner_user_id=? ORDER BY created_at DESC LIMIT 50", (workspace_id, user["id"])).fetchall()
        return {"jobs": [jobs.get(workspace_id, user, row[0]) for row in ids]}

    @app.get("/api/workspaces/{workspace_id}/ctfd/jobs/{job_id}")
    def get_ctfd_job(workspace_id: str, job_id: str, user=Depends(require_auth)):
        return {"job": jobs.get(workspace_id, user, job_id)}

    @app.post("/api/workspaces/{workspace_id}/ctfd/jobs/{job_id}/cancel")
    def cancel_ctfd_job(workspace_id: str, job_id: str, user=Depends(require_auth)):
        return jobs.cancel(workspace_id, user, job_id)

    @app.post("/api/workspaces/{workspace_id}/ctfd/jobs/{job_id}/retry", status_code=202)
    def retry_ctfd_job(workspace_id: str, job_id: str, body: dict, user=Depends(require_auth)):
        with jobs.workspace_slot(workspace_id):
            return call(jobs.start, workspace_id, user, body, job_id)
