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

import sys
import urllib.error
import urllib.request
from typing import NoReturn
from urllib.parse import urlparse

from sanitizer import sanitize

FETCH_TIMEOUT_SECONDS = 15
MAX_FETCH_BYTES = 5 * 1024 * 1024  # 5 MB raw cap before sanitizer truncates to 20 KB
USER_AGENT = "safe-fetch/0.1.2 (+https://github.com/sharkyger/safe-fetch)"


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
            raise urllib.error.HTTPError(
                newurl, 403, "redirect to disallowed URL", headers, fp
            ) from None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _fetch(url: str) -> bytes:
    # Scheme is validated up-front in _validate(); the urllib calls
    # below would otherwise warrant S310. The noqa is the documented
    # mitigation, not silent suppression.
    opener = urllib.request.build_opener(_ValidatingRedirectHandler())
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})  # noqa: S310
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
