"""In-container entrypoint for the ``safe-fetch:latest`` image.

Invoked as ``python3 /app/entrypoint.py <url>``. Fetches the URL via
stdlib ``urllib`` (no third-party HTTP client; smaller attack surface
and no curl in the image), runs the Layer-2 sanitizer, and writes the
``<UNTRUSTED-WEB url="...">`` envelope to stdout.

This file lives inside the container only. Host-side validation
(scheme, control chars, allowlist routing) happens in
``src/safe_fetch/cli.py``; what arrives here is already trusted to be
a syntactically-valid http/https URL. Defense-in-depth: we still
verify the scheme here so a future regression in the host code can't
silently smuggle ``file://`` into the container.
"""

from __future__ import annotations

import os
import sys
import urllib.error
import urllib.request
from typing import NoReturn
from urllib.parse import urlparse

from sanitizer import sanitize

FETCH_TIMEOUT_SECONDS = 15
MAX_FETCH_BYTES = 5 * 1024 * 1024  # 5 MB raw cap before sanitizer truncates to 20 KB
USER_AGENT = "safe-fetch/0.3.0 (+https://github.com/sharkyger/safe-fetch)"

# Optional search-provider auth header, forwarded by the host as an env
# var (host-side ``cli._search_header_flags``). Only consulted for the
# search flow; a plain fetch never sets it.
SEARCH_HEADER_ENV = "SAFE_FETCH_SEARCH_HEADER"


def _die(msg: str, code: int = 2) -> NoReturn:
    print(f"safe-fetch: {msg}", file=sys.stderr)
    sys.exit(code)


def _validate(url: str) -> None:
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        _die(f"unsupported scheme {p.scheme!r}; only http/https allowed")
    if not p.netloc:
        _die("URL has no host")


class _ValidatingRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-runs ``_validate`` on every redirect target.

    Python's default ``HTTPRedirectHandler`` already restricts redirects
    to a small set of schemes (http/https/ftp), but it does not invoke
    our own host validation. Without this handler a 30x response could
    redirect a sanctioned http/https request into a URL that fails our
    contract (missing host, unsupported scheme via a future urllib
    change, etc.). The handler converts a validation failure into a 403
    HTTPError so ``_fetch``'s existing exception path reports it.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        try:
            _validate(newurl)
        except SystemExit:
            raise urllib.error.HTTPError(newurl, 403, "redirect to disallowed URL", headers, fp) from None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _search_header() -> tuple[str, str] | None:
    """Parse the optional search auth header from the environment.

    Returns ``(name, value)``, or ``None`` when the variable is blank/unset
    (no auth header). A non-blank but malformed value (no ``:`` or an empty
    name) exits via ``_die`` rather than silently degrading to no-auth —
    fail-closed. All control characters (notably CR/LF) are stripped so a
    crafted value cannot inject additional request headers; the value is
    never logged — it only feeds the request below.
    """
    raw = os.environ.get(SEARCH_HEADER_ENV, "")
    if not raw.strip():
        return None  # no auth configured — proceed without a header
    # A header is a single line: keep only the first line (``splitlines``
    # covers CR, LF, CRLF and the exotic Unicode/C1 separators) so any
    # injected trailing lines are dropped entirely, then strip remaining
    # control chars (C0, DEL, C1) from what's left.
    lines = raw.splitlines()
    line = lines[0] if lines else ""
    cleaned = "".join(c for c in line if not (ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F))
    name, sep, value = cleaned.partition(":")
    name, value = name.strip(), value.strip()
    # A non-blank value that doesn't parse as "Name: value" is a
    # misconfiguration — fail loud rather than silently dropping the auth
    # header and sending the request unauthenticated.
    if not sep or not name:
        _die(f"malformed {SEARCH_HEADER_ENV}: expected 'Name: value'")
    return name, value


def _fetch(url: str) -> bytes:
    # Scheme is validated up-front in _validate(); the urllib calls
    # below would otherwise warrant S310. The noqa is the documented
    # mitigation, not silent suppression.
    opener = urllib.request.build_opener(_ValidatingRedirectHandler())
    headers = {"User-Agent": USER_AGENT}
    extra = _search_header()
    if extra is not None:
        headers[extra[0]] = extra[1]
    req = urllib.request.Request(url, headers=headers)  # noqa: S310
    try:
        with opener.open(req, timeout=FETCH_TIMEOUT_SECONDS) as r:  # noqa: S310
            return r.read(MAX_FETCH_BYTES + 1)
    except urllib.error.HTTPError as e:
        _die(f"HTTP {e.code} {e.reason}", code=2)
    except urllib.error.URLError as e:
        _die(f"URL error: {e.reason}", code=2)
    except TimeoutError:
        _die(f"timeout after {FETCH_TIMEOUT_SECONDS}s", code=2)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        _die("Usage: entrypoint.py <url>")
    url = argv[1]
    _validate(url)
    raw = _fetch(url)
    if len(raw) > MAX_FETCH_BYTES:
        # Body exceeded the raw cap. Truncate; the sanitizer's own
        # 20 KB output cap will compress it further.
        raw = raw[:MAX_FETCH_BYTES]
    # Decode permissively — sanitizer needs str. Errors-replace so a
    # mis-encoded page can't crash the container.
    text = raw.decode("utf-8", errors="replace")
    result = sanitize(text, url=url)
    sys.stdout.write(result.content)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
