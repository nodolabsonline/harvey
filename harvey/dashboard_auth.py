"""Who may use the dashboard API.

The dashboard binds to loopback, but loopback is not an identity: any local
process, any page open in the operator's browser (cross-origin requests can
still *send*), and any DNS name pointed at 127.0.0.1 can reach the port. So
every request passes, in order:

1. Host: one Host header naming a loopback address (``localhost``,
   127.0.0.0/8, ``[::1]``) with an optional port, or a hostname listed in
   ``HARVEY_DASHBOARD_ALLOWED_HOSTS``. Anything else, including a rebinding
   name that resolves to 127.0.0.1, is refused before the token is looked
   at. ``*`` is not a hostname.
2. Browser provenance: a request carrying ``Origin`` must be exactly
   ``http://`` plus that Host header, or an origin listed in
   ``HARVEY_DASHBOARD_ALLOWED_ORIGINS`` (``http://`` or ``https://``, no
   path). ``Sec-Fetch-Site`` must be ``same-origin`` or ``none``. (A
   top-level navigation to ``/`` is the one exception: the shell carries
   no data.) No CORS headers are ever sent, so preflights fail.
   ``X-Forwarded-Host`` and ``X-Forwarded-Proto`` are ignored.
3. Public shell: only ``GET``/``HEAD`` of ``/`` and ``/static/*`` (HTML, CSS,
   JS, fonts; no data, no token) skip authentication.
4. Bearer token: everything else needs ``Authorization: Bearer <token>``,
   compared in constant time. Cookies and query strings are never read, so
   a browser can't attach the token on an attacker's behalf, and a
   cross-origin page can neither read it nor set the header without a
   preflight this server never approves. Non-browser clients need it too.
5. Mutations with a body must be ``application/json``.

The token is created once in ``data/dashboard-token`` (owner-only, written
to a private temporary file and published with an exclusive link so it is
never seen half-written, never follows a symlink, and never replaces an
existing file). An existing token is used only if it is a regular file owned
by this user with no group/other permissions and a well-formed value;
otherwise the API stays locked (fail closed) and the error says what to do.

On Windows, POSIX permission bits mean nothing: the file gets whatever ACL
the folder grants, and Harvey doesn't pretend otherwise (see README).

``HARVEY_DASHBOARD_BIND`` is the listen address. Unset, the server binds to
loopback. A non-loopback address is accepted only together with at least
one allowed host. Neither switch turns the bearer check off.

This does not protect against code already running as the same OS user,
which can read the token file (or the database) directly.
"""

from __future__ import annotations

import errno
import hmac
import ipaddress
import json
import os
import re
import secrets
import stat
import threading
import time
from pathlib import Path

TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43,128}")
_PORT_RE = re.compile(r":[0-9]{1,5}")
_IS_WINDOWS = os.name == "nt"

# Unset (or blank) keeps today's loopback-only dashboard. Names are exact:
# a star is a configuration error, never "allow everything".
BIND_ENV = "HARVEY_DASHBOARD_BIND"
ALLOWED_HOSTS_ENV = "HARVEY_DASHBOARD_ALLOWED_HOSTS"
ALLOWED_ORIGINS_ENV = "HARVEY_DASHBOARD_ALLOWED_ORIGINS"

SECURITY_HEADERS = [
    (b"cache-control", b"no-store"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    # Inline handlers/styles are how the existing UI is written, so
    # 'unsafe-inline' stays; connect-src 'self' still keeps fetches local.
    (b"content-security-policy",
     b"default-src 'self'; script-src 'self' 'unsafe-inline'; "
     b"style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; "
     b"connect-src 'self'; object-src 'none'; base-uri 'none'; "
     b"form-action 'none'; frame-ancestors 'none'"),
]

_UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


class TokenError(Exception):
    """The dashboard token can't be used; the API stays locked."""


class _ExtraLinkError(TokenError):
    """The token file has another hard link (briefly true while another
    dashboard publishes it: see _publish_token)."""


class _WindowsReadBusyError(TokenError):
    """Windows refused an open that may overlap token publication."""


# ── Token file ──


def _check_open_file(fd: int, path: Path):
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode):
        raise TokenError(f"{path} is not a regular file. Remove it and restart the dashboard.")
    if _IS_WINDOWS:
        return  # ACLs, not mode bits: see the module docstring
    if st.st_uid != os.geteuid():
        raise TokenError(f"{path} is owned by another user. Remove it and restart "
                         "the dashboard to create a new token.")
    if st.st_mode & 0o077:
        raise TokenError(f"{path} is readable or writable by other users "
                         f"(mode {stat.S_IMODE(st.st_mode):o}), so the token may be known. "
                         "Remove it and restart the dashboard to create a new one.")
    if st.st_nlink != 1:
        raise _ExtraLinkError(f"{path} has other hard links. Remove it and restart "
                              "the dashboard.")


def _read_token(path: Path) -> str | None:
    """The stored token, None if there is no file, TokenError if unusable."""
    if _IS_WINDOWS and os.path.islink(path):
        raise TokenError(f"{path} is a symbolic link. Remove it and restart the dashboard.")
    flags = (os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
             | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    try:
        fd = os.open(path, flags)
    except FileNotFoundError:
        return None
    except OSError as e:
        if e.errno in (errno.ELOOP, errno.EMLINK):
            raise TokenError(f"{path} is a symbolic link. Remove it and restart "
                             "the dashboard.") from e
        error_type = TokenError
        # The CRT can reduce sharing violations to EACCES without winerror.
        # Real ACL denials use the same code; they still fail closed after
        # the bounded settling window, without replacing the token.
        if _IS_WINDOWS and (e.errno == errno.EACCES
                            or getattr(e, "winerror", None) in (5, 32, 33)):
            error_type = _WindowsReadBusyError
        raise error_type(f"Can't read {path}: {e.strerror}.") from e
    try:
        _check_open_file(fd, path)
        data = os.read(fd, 4097)
    finally:
        os.close(fd)
    try:
        token = data.decode("ascii").strip()
    except UnicodeDecodeError:
        token = ""
    if len(data) > 4096 or not TOKEN_RE.fullmatch(token):
        raise TokenError(f"{path} doesn't hold a valid token. Remove it and restart "
                         "the dashboard to create a new one.")
    return token


def _publish_token(path: Path, token: str):
    """Write the token where nobody else can read it, then publish it under
    its final name without ever replacing an existing file."""
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    flags = (os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
             | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_BINARY", 0))
    fd = os.open(tmp, flags, 0o600)
    try:
        if not _IS_WINDOWS:
            os.fchmod(fd, 0o600)  # exact, whatever the umask
        os.write(fd, (token + "\n").encode("ascii"))
        os.fsync(fd)
    finally:
        os.close(fd)
    try:
        if _IS_WINDOWS:
            os.rename(tmp, path)  # refuses to replace an existing file
        else:
            try:
                os.link(tmp, path)  # atomic; refuses to replace anything
            except FileExistsError:
                raise
            except OSError:
                # Filesystems without hard links: exclusive create instead.
                fd = os.open(path, flags, 0o600)
                try:
                    os.fchmod(fd, 0o600)
                    os.write(fd, (token + "\n").encode("ascii"))
                    os.fsync(fd)
                finally:
                    os.close(fd)
    except FileExistsError:
        pass  # another dashboard won the race; use its token
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def _read_token_settled(path: Path) -> str | None:
    """Wait at most 50 short intervals for publication-related read failures.

    Persistent access errors or extra links are still refused. Token contents
    and all other file-security checks are never retried or relaxed.
    """
    for _ in range(50):
        try:
            return _read_token(path)
        except (_ExtraLinkError, _WindowsReadBusyError):
            time.sleep(0.01)
    return _read_token(path)


def load_or_create_token(path: Path) -> str:
    path = Path(path)
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as e:
        raise TokenError(f"Can't create {path.parent}: {e.strerror}.") from e
    token = _read_token_settled(path)
    if token is not None:
        return token
    try:
        _publish_token(path, secrets.token_urlsafe(32))
    except OSError as e:
        raise TokenError(f"Can't create {path}: {e.strerror}.") from e
    token = _read_token_settled(path)
    if token is None:
        raise TokenError(f"{path} disappeared while it was being created. Restart the dashboard.")
    return token


class TokenStore:
    """The token for this process: loaded (or created) once, then cached."""

    def __init__(self, path: Path):
        self._lock = threading.Lock()
        self.configure(path)

    def configure(self, path: Path):
        with self._lock:
            self.path = Path(path)
            self._token: str | None = None

    def get(self) -> str:
        with self._lock:
            if self._token is None:
                self._token = load_or_create_token(self.path)
            return self._token


# ── Request checks ──


def parse_host(value: str) -> str | None:
    """The hostname from a Host header value, or None if malformed."""
    if not value or len(value) > 262:
        return None
    if any(ord(c) <= 32 or ord(c) >= 127 for c in value):
        return None
    if value.startswith("["):
        end = value.find("]")
        if end < 0:
            return None
        host, rest = value[1:end], value[end + 1:]
        if not host or ":" not in host or "%" in host:
            return None  # brackets are for IPv6 literals only, without a zone ID
    else:
        host, sep, port = value.partition(":")
        rest = sep + port
        if not host or ":" in port:
            return None
    if rest:
        if not _PORT_RE.fullmatch(rest) or not 0 < int(rest[1:]) <= 65535:
            return None
    return host.lower()


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    if "%" in host:
        return False  # IPv6 zone IDs (::1%lo0): ipaddress calls them loopback
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


# Filled from .env at startup when the process environment left a key blank.
# Process environment always wins over the file.
_file_fallback: dict[str, str] = {}


def set_proxy_file_values(values: dict[str, str]):
    """Replace the .env fallback for the three proxy variables."""
    _file_fallback.clear()
    for key in (BIND_ENV, ALLOWED_HOSTS_ENV, ALLOWED_ORIGINS_ENV):
        value = (values.get(key) or "").strip()
        if value:
            _file_fallback[key] = value


def proxy_setting(name: str) -> str:
    """Process environment, else the value loaded from .env, else blank."""
    process = os.environ.get(name, "").strip()
    if process:
        return process
    return _file_fallback.get(name, "").strip()


def _csv_env(name: str) -> tuple[str, ...] | None:
    """Comma-separated entries, or None when the variable is unset or blank."""
    raw = proxy_setting(name)
    if not raw:
        return None
    items = tuple(part.strip() for part in raw.split(",") if part.strip())
    return items or None


def canonical_host_name(value: str) -> str | None:
    """A hostname from an allow-list entry. The port is not part of the name."""
    if not value or "*" in value or "://" in value or "/" in value or "@" in value:
        return None
    return parse_host(value)


def canonical_origin(value: str) -> str | None:
    """``http(s)://host[:port]`` with no path, user or wildcard."""
    if not value or "*" in value or "@" in value or "\\" in value:
        return None
    text = value.strip().lower()
    if text.endswith("/"):
        text = text[:-1]
    if text.startswith("https://"):
        scheme, rest = "https", text[len("https://"):]
    elif text.startswith("http://"):
        scheme, rest = "http", text[len("http://"):]
    else:
        return None
    if not rest or any(c in rest for c in "/?#"):
        return None
    if parse_host(rest) is None:
        return None
    return f"{scheme}://{rest}"


def exposure_error() -> str | None:
    """Why the proxy settings cannot be used, or None when they are empty or safe.

    An illegal list fails closed: it does not widen who is accepted.
    """
    hosts = _csv_env(ALLOWED_HOSTS_ENV)
    if hosts is not None:
        for item in hosts:
            if "*" in item:
                return (f"{ALLOWED_HOSTS_ENV} must list hostnames separated by commas. "
                        "'*' is not accepted.")
            if canonical_host_name(item) is None:
                return f"{ALLOWED_HOSTS_ENV} has an invalid host: {item!r}."
    origins = _csv_env(ALLOWED_ORIGINS_ENV)
    if origins is not None:
        for item in origins:
            if "*" in item:
                return (f"{ALLOWED_ORIGINS_ENV} must list http:// or https:// origins "
                        "separated by commas. '*' is not accepted.")
            if canonical_origin(item) is None:
                return f"{ALLOWED_ORIGINS_ENV} has an invalid origin: {item!r}."
    return None


def allowed_hosts() -> tuple[str, ...]:
    """Extra Host names. Empty when unset or when the list is not safe."""
    if exposure_error():
        return ()
    items = _csv_env(ALLOWED_HOSTS_ENV)
    if not items:
        return ()
    names = []
    for item in items:
        name = canonical_host_name(item)
        if name is None:
            return ()
        names.append(name)
    return tuple(names)


def allowed_origins() -> tuple[str, ...]:
    """Extra browser origins. Empty when unset or when the list is not safe."""
    if exposure_error():
        return ()
    items = _csv_env(ALLOWED_ORIGINS_ENV)
    if not items:
        return ()
    origins = []
    for item in items:
        origin = canonical_origin(item)
        if origin is None:
            return ()
        origins.append(origin)
    return tuple(origins)


def host_permitted(host: str) -> bool:
    return is_loopback(host) or host in allowed_hosts()


def origin_permitted(origin: str, host_header: str) -> bool:
    """The loopback rule (``http://`` plus the Host header) plus a named list."""
    if origin.lower() == f"http://{host_header}":
        return True
    canon = canonical_origin(origin)
    return bool(canon) and canon in allowed_origins()


def is_public_path(method: str, path: str) -> bool:
    if method not in ("GET", "HEAD"):
        return False
    if path == "/":
        return True
    if not path.startswith("/static/"):
        return False
    return all(seg not in ("", ".", "..") for seg in path[len("/static/"):].split("/"))


def bearer_ok(header_values: list[str], token: str) -> bool:
    if len(header_values) != 1:
        return False
    scheme, _, presented = header_values[0].partition(" ")
    if scheme.lower() != "bearer":
        return False
    presented = presented.strip()
    return hmac.compare_digest(presented.encode("utf-8", "replace"), token.encode("ascii"))


def _is_json(content_type: str) -> bool:
    media = content_type.split(";", 1)[0].strip().lower()
    return media == "application/json"


class DashboardGuard:
    """ASGI middleware applying the checks in the module docstring to every
    request, and the security headers to every response."""

    def __init__(self, app, store: TokenStore):
        self.app = app
        self.store = store

    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            return await self.app(scope, receive, send)
        if scope["type"] != "http":
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return

        headers: dict[str, list[str]] = {}
        for k, v in scope.get("headers") or []:
            headers.setdefault(k.decode("latin-1").lower(), []).append(v.decode("latin-1"))

        async def send_secured(message):
            if message["type"] == "http.response.start":
                existing = [(k, v) for k, v in message.get("headers", [])
                            if k.lower() not in {h for h, _ in SECURITY_HEADERS}]
                message = {**message, "headers": existing + SECURITY_HEADERS}
            await send(message)

        async def deny(status: int, code: str, message: str, extra=()):
            body = json.dumps({"error": code, "message": message}).encode()
            await send_secured({"type": "http.response.start", "status": status,
                                "headers": [(b"content-type", b"application/json"),
                                            (b"content-length", str(len(body)).encode()),
                                            *extra]})
            await send_secured({"type": "http.response.body", "body": body})

        method = scope.get("method", "GET").upper()
        path = scope.get("path", "")

        # 1. Host, before anything else.
        hosts = headers.get("host", [])
        host = parse_host(hosts[0]) if len(hosts) == 1 else None
        if host is None or not host_permitted(host):
            return await deny(400, "bad_host",
                              "This dashboard only answers to localhost / 127.0.0.1.")
        host_header = hosts[0].lower()

        # 2. Browser provenance. Forwarded headers are not a second Host.
        public = is_public_path(method, path)
        navigation = (method in ("GET", "HEAD") and path == "/"
                      and headers.get("sec-fetch-mode", [""])[0] == "navigate"
                      and headers.get("sec-fetch-dest", [""])[0] == "document")
        origins = headers.get("origin", [])
        if origins and (len(origins) != 1
                        or not origin_permitted(origins[0], host_header)):
            if not navigation:
                return await deny(403, "cross_origin", "Cross-origin requests are refused.")
        site = headers.get("sec-fetch-site", [])
        if site and site[0].lower() not in ("same-origin", "none") and not navigation:
            return await deny(403, "cross_origin", "Cross-site requests are refused.")

        if public:
            return await self.app(scope, receive, send_secured)

        # 3. Token (fail closed when it can't be loaded).
        try:
            token = self.store.get()
        except TokenError as e:
            return await deny(503, "token_unavailable", str(e))
        if not bearer_ok(headers.get("authorization", []), token):
            return await deny(401, "unauthorized",
                              "Open the link printed by 'harvey dashboard' to unlock.",
                              extra=[(b"www-authenticate", b'Bearer realm="harvey"')])

        # 4. Mutations carry JSON or nothing.
        if method in _UNSAFE_METHODS:
            length = headers.get("content-length", ["0"])[0].strip()
            has_body = bool(headers.get("transfer-encoding")) or length not in ("", "0")
            if has_body and not _is_json(headers.get("content-type", [""])[0]):
                return await deny(415, "unsupported_media_type",
                                  "Request bodies must be application/json.")

        return await self.app(scope, receive, send_secured)
