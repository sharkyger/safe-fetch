"""Web-search support for safe-fetch.

A search is "fetch a URL the user templated from a query." safe-fetch
ships with **no** search provider configured — the user supplies a URL
template (and an optional auth header) for whatever search backend they
choose. The query is percent-encoded and substituted into the template;
the resulting URL is then run through the exact same hardened-container
fetch + Layer-2 sanitizer + ``<UNTRUSTED-WEB>`` envelope path as a plain
fetch. Search results are untrusted data, identical to a fetched page.

This module holds the host-side pure logic:

- ``config_path`` / ``load_config`` / ``save_config`` — the (optional)
  ``search.json`` config, with env-var overrides for power users.
- ``template_error`` / ``query_error`` — input validation.
- ``build_search_url`` — query→URL with percent-encoding (the first line
  of envelope-breakout defense; the in-container ``_sanitize_envelope_url``
  html-escape is the second).

There is no bundled allowlist and no bundled provider: ``load_config``
returns ``None`` until the user opts in, and the CLI fails closed on
that. The auth header is sent as an HTTP request header inside the
container, never interpolated into the URL, so a provider key never
reaches the envelope the agent reads.
"""

from __future__ import annotations

import contextlib
import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import quote, urlparse

# Query placeholder the user puts in their URL template.
QUERY_PLACEHOLDER = "{query}"

# Power-user env overrides (take precedence over the config file). The
# header var name is reused verbatim as the in-container env that
# ``docker/entrypoint.py`` reads, so the value flows host → container
# under one stable name.
ENV_URL = "SAFE_FETCH_SEARCH_URL"
ENV_HEADER = "SAFE_FETCH_SEARCH_HEADER"


def _has_control_chars(s: str) -> bool:
    # C0 (0x00-0x1f), DEL (0x7f), and C1 (0x80-0x9f) controls — matches the
    # sanitizer's envelope-URL control class (_URL_CONTROL_RE).
    return any(ord(c) < 0x20 or 0x7F <= ord(c) <= 0x9F for c in s)


class SearchConfigError(Exception):
    """The search config file exists but is malformed or incomplete."""


@dataclass
class SearchConfig:
    """A configured search backend. ``auth_header`` is a full header line
    (e.g. ``"X-Subscription-Token: abc"``) sent inside the container."""

    url_template: str
    auth_header: str | None = None


@dataclass
class SaveResult:
    """Outcome of ``save_config`` (for the wizard's summary line)."""

    kind: str  # 'create' or 'update'
    path: Path


def config_path() -> Path:
    """Return the search config path, honoring ``XDG_CONFIG_HOME``.

    Defaults to ``~/.config/safe-fetch/search.json``.
    """
    base = os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / "safe-fetch" / "search.json"


def load_config() -> SearchConfig | None:
    """Load the search config, env overrides first, else the file.

    Returns ``None`` when nothing is configured — the caller must fail
    closed. Raises ``SearchConfigError`` if the file exists but is
    unreadable / not JSON / missing ``url_template``.
    """
    env_url = os.environ.get(ENV_URL, "").strip()
    raw_env_header = os.environ.get(ENV_HEADER)
    env_header = raw_env_header.strip() if raw_env_header is not None else ""
    header_set = raw_env_header is not None

    if env_url:
        return SearchConfig(url_template=env_url, auth_header=env_header or None)

    path = config_path()
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise SearchConfigError(f"could not read search config at {path}: {e}") from e
    if not isinstance(data, dict):
        raise SearchConfigError(f"search config at {path} must be a JSON object")
    url_template = data.get("url_template")
    if not url_template:
        raise SearchConfigError(f"search config at {path} is missing 'url_template'")
    if not isinstance(url_template, str):
        raise SearchConfigError(f"search config at {path}: 'url_template' must be a string")
    file_auth = data.get("auth_header")
    if file_auth is not None and not isinstance(file_auth, str):
        raise SearchConfigError(f"search config at {path}: 'auth_header' must be a string")
    # A set env header overrides the file — even when blank: an explicit
    # SAFE_FETCH_SEARCH_HEADER="" disables the stored header. When the var is
    # unset, the file value is used, so a user can keep the URL in the file
    # and supply the secret via the environment.
    auth = (env_header or None) if header_set else (file_auth or None)
    return SearchConfig(url_template=url_template, auth_header=auth)


def save_config(config: SearchConfig, *, dry_run: bool = False) -> SaveResult:
    """Write the search config atomically with owner-only (0600) perms."""
    path = config_path()
    kind = "update" if path.exists() else "create"
    if dry_run:
        return SaveResult(kind, path)

    path.parent.mkdir(parents=True, exist_ok=True)
    # Best-effort; a pre-existing dir's perms are the user's call.
    with contextlib.suppress(OSError):
        path.parent.chmod(0o700)

    data: dict[str, str] = {"url_template": config.url_template}
    if config.auth_header:
        data["auth_header"] = config.auth_header
    payload = json.dumps(data, indent=2) + "\n"

    # Atomic: write a sibling temp file (same dir → same filesystem),
    # tighten perms, then rename over the target.
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".search.", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(payload.encode("utf-8"))
        tmp.chmod(0o600)
        tmp.replace(path)
    except OSError:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    return SaveResult(kind, path)


def template_error(template: str) -> str | None:
    """Return an error message if the URL template is unusable, else None.

    Beyond scheme + placeholder presence, this pins the host: the
    ``{query}`` placeholder must live in the path or query string, never
    in the scheme or netloc, so the (attacker-influenceable) query can
    never redirect the request to a different host or port.
    """
    if not template or not template.strip():
        return "search URL template is required"
    if _has_control_chars(template):
        return "search URL template contains control characters"
    if QUERY_PLACEHOLDER not in template:
        return f"search URL template must contain the {QUERY_PLACEHOLDER} placeholder"
    # Parse the raw template directly and require the placeholder to live in
    # the path/query, not the scheme or netloc — so the query can never
    # control the destination host or port.
    parsed = urlparse(template)
    if parsed.scheme not in ("http", "https"):
        return f"unsupported scheme {parsed.scheme!r}; only http/https allowed"
    if QUERY_PLACEHOLDER in parsed.scheme or QUERY_PLACEHOLDER in parsed.netloc:
        return f"the {QUERY_PLACEHOLDER} placeholder must be in the path or query string, not the host"
    if QUERY_PLACEHOLDER in parsed.fragment:
        # A fragment (#...) never leaves the client, so the query would
        # never reach the backend — every search would send no query.
        return f"the {QUERY_PLACEHOLDER} placeholder must be in the path or query string, not the URL fragment"
    if not parsed.netloc:
        return "search URL template has no host"
    return None


def query_error(query: str) -> str | None:
    """Return an error message if the query is unusable, else None."""
    if not query or not query.strip():
        return "search query is required"
    if _has_control_chars(query):
        return "query contains control characters"
    return None


def build_search_url(template: str, query: str) -> str:
    """Substitute the percent-encoded query into the template.

    ``safe=""`` encodes everything reserved — spaces, ``&``, ``<``,
    ``>``, ``"`` — so the query cannot inject extra params or smuggle
    envelope metacharacters into the URL.
    """
    return template.replace(QUERY_PLACEHOLDER, quote(query, safe=""))
