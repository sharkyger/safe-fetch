"""Host-side CLI for safe-fetch.

Two modes:

  ``safe-fetch <url>``
      Pre-flight Docker, validate the URL, run the locked-down
      ``safe-fetch:latest`` image, stream sanitized stdout back.

  ``safe-fetch search <query>``
      Turn a query into a URL via the user-configured search template and
      run it through the same hardened fetch path. Ships with no provider
      configured — ``safe-fetch search --setup`` writes the config. See
      ``safe_fetch.search`` / ``safe_fetch.search_setup``.

  ``safe-fetch --install-claude-hooks``
      Idempotently install the four Claude Code hooks, five operator
      slash commands, and CLAUDE.md Layer-4 snippet into
      ``~/.claude/`` (or ``--install-target <path>``). Pair with
      ``--uninstall-claude-hooks`` and ``--dry-run``. Implementation
      lives in ``safe_fetch.installer``.

Every flag in ``DOCKER_FLAGS`` is asserted by ``tests/test_safe_fetch_cli.py``.
A missing or relaxed flag is a security regression — change the test
deliberately if you intend to alter the contract.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

from safe_fetch import __version__, search

IMAGE_NAME = "safe-fetch:latest"
USAGE = (
    "Usage: safe-fetch <url>\n"
    "       safe-fetch search <query>\n"
    "       safe-fetch search --setup\n"
    "       safe-fetch --install-claude-hooks [--install-target PATH] [--dry-run]\n"
    "       safe-fetch --uninstall-claude-hooks [--install-target PATH] [--dry-run]"
)


# Locked-down docker-run flag set. Order matches the human-readable
# rationale in README.md and the test that asserts each flag.
DOCKER_FLAGS = [
    "--rm",
    "-i",
    "--network=bridge",
    "--read-only",
    "--tmpfs",
    "/tmp:rw,size=8m,noexec,nosuid",  # noqa: S108  # nosec B108 — docker tmpfs spec, not a host-side temp path
    "--cap-drop=ALL",
    "--security-opt",
    "no-new-privileges",
    "--user",
    "nobody",
    "--memory=256m",
    "--memory-swap=256m",
    "--pids-limit=50",
    "--cpus=0.5",
    "--ulimit",
    "nofile=128:128",
]


DOCKER_MISSING_MSG = (
    "safe-fetch: Docker is not available.\n"
    "Install Docker Desktop (or start the daemon) and ensure `docker info`\n"
    "exits 0, then retry. https://docs.docker.com/get-docker/"
)


def _validate_url(url: str) -> str | None:
    """Return an error message if the URL is unsafe, else None."""
    if not url:
        return "URL is required"
    if any(ord(c) < 0x20 for c in url):
        return "URL contains control characters"
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return f"unsupported scheme {parsed.scheme!r}; only http/https allowed"
    if not parsed.netloc:
        return "URL has no host"
    return None


def _check_docker() -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (subprocess.TimeoutExpired, OSError):
        return False
    return result.returncode == 0


# Proxy env vars that urllib (in the container) honors. Forwarded
# verbatim — safe-fetch's job here is composition with proxy-based
# tools like pipelock, not parsing the values. Order is stable so the
# docker argv is deterministic for tests and audit.
_PROXY_VARS: tuple[str, ...] = ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY")


def _proxy_flags() -> list[str]:
    """Return ``-e VAR=value`` pairs for any non-empty proxy env vars.

    Both uppercase (``HTTPS_PROXY``) and lowercase (``https_proxy``)
    forms are honored — Linux convention treats both as standard. If
    both are set, the uppercase value wins (it's the documented
    canonical form). Empty-string values are treated as unset.
    """
    flags: list[str] = []
    for var in _PROXY_VARS:
        val = os.environ.get(var) or os.environ.get(var.lower(), "")
        # Treat whitespace-only values as unset too (same as empty
        # string). A user setting HTTPS_PROXY="   " almost certainly
        # didn't intend a single-space proxy URL.
        if val and val.strip():
            flags.extend(["-e", f"{var}={val}"])
    return flags


def _build_docker_command(url: str, image: str = IMAGE_NAME) -> list[str]:
    """Pure: assemble the locked-down docker-run argv for the given URL.

    The URL is the LAST argv entry. Anything before the image name is
    flags interpreted by docker itself; positioning the URL after the
    image makes accidental flag-injection impossible even if a future
    refactor mishandles validation.

    ``HTTPS_PROXY`` / ``HTTP_PROXY`` / ``NO_PROXY`` are forwarded into
    the container via ``-e`` flags (positioned before the image name)
    so the in-container urllib honors them. When none are set the
    argv is identical to v0.1.x.
    """
    return ["docker", "run", *DOCKER_FLAGS, *_proxy_flags(), image, url]


# ── search ──────────────────────────────────────────────────────────


def _search_header_flags(auth_header: str | None) -> list[str]:
    """Return ``-e SAFE_FETCH_SEARCH_HEADER=...`` for a configured auth header.

    The header travels into the container as an env var (same mechanism
    as the proxy passthrough) and is sent as an HTTP request header by
    the in-container fetch — it is NEVER interpolated into the URL, so a
    provider key never reaches the ``<UNTRUSTED-WEB url=...>`` envelope.
    Empty / whitespace-only values are treated as unset.
    """
    if not auth_header or not auth_header.strip():
        return []
    return ["-e", f"{search.ENV_HEADER}={auth_header}"]


def _build_search_docker_command(url: str, auth_header: str | None = None, image: str = IMAGE_NAME) -> list[str]:
    """Assemble the locked-down docker-run argv for a search URL.

    Identical to ``_build_docker_command`` plus the optional auth-header
    env flag. The URL stays the final positional arg (same flag-injection
    invariant).
    """
    return [
        "docker",
        "run",
        *DOCKER_FLAGS,
        *_proxy_flags(),
        *_search_header_flags(auth_header),
        image,
        url,
    ]


def _run_search_setup(*, dry_run: bool = False) -> int:
    # Lazy import keeps the interactive wizard (and getpass) out of the
    # hot fetch path.
    from safe_fetch import search_setup

    return search_setup.run_setup(dry_run=dry_run)


def _run_search(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="safe-fetch search",
        description="Run a web search and return results as <UNTRUSTED-WEB>-wrapped data.",
    )
    parser.add_argument("query", nargs="?", help="search query (omit with --setup)")
    parser.add_argument(
        "--setup",
        action="store_true",
        help="Interactively configure a search backend (writes search.json).",
    )
    parser.add_argument("--dry-run", action="store_true", help="With --setup: show changes without writing.")
    try:
        parsed = parser.parse_args(argv)
    except SystemExit as e:
        return int(e.code) if isinstance(e.code, int) else 0

    if parsed.setup:
        return _run_search_setup(dry_run=parsed.dry_run)

    if not parsed.query:
        print("safe-fetch: a search query is required (or use --setup)", file=sys.stderr)
        print(USAGE, file=sys.stderr)
        return 2

    qerr = search.query_error(parsed.query)
    if qerr:
        print(f"safe-fetch: {qerr}", file=sys.stderr)
        return 2

    try:
        config = search.load_config()
    except search.SearchConfigError as e:
        print(f"safe-fetch: {e}", file=sys.stderr)
        return 2
    if config is None:
        print(
            "safe-fetch: no search backend configured. Run `safe-fetch search --setup` to set one up.",
            file=sys.stderr,
        )
        return 2

    # Defense-in-depth: validate the template on every run (it may come
    # from the env or a hand-edited file, not just the wizard) so the
    # query can never control the destination host.
    terr = search.template_error(config.url_template)
    if terr:
        print(f"safe-fetch: {terr}", file=sys.stderr)
        return 2

    url = search.build_search_url(config.url_template, parsed.query)
    err = _validate_url(url)
    if err:
        print(f"safe-fetch: {err}", file=sys.stderr)
        return 2
    if not _check_docker():
        print(DOCKER_MISSING_MSG, file=sys.stderr)
        return 2
    cmd = _build_search_docker_command(url, auth_header=config.auth_header)
    return subprocess.run(cmd, check=False).returncode


# ── installer dispatch ──────────────────────────────────────────────


def _run_installer(install: bool, target: Path, dry_run: bool) -> int:
    from safe_fetch import installer

    label = "install" if install else "uninstall"
    try:
        actions = (
            installer.install(target, dry_run=dry_run) if install else installer.uninstall(target, dry_run=dry_run)
        )
    except installer.InstallerError as e:
        print(f"safe-fetch: {label} failed: {e}", file=sys.stderr)
        return 2

    prefix = "[dry-run] " if dry_run else ""
    for a in actions:
        suffix = f" — {a.detail}" if a.detail else ""
        print(f"{prefix}{a.kind:>6}  {a.path}{suffix}")
    if not actions:
        print(f"{prefix}{label}: nothing to do")
    return 0


# ── argument parsing ────────────────────────────────────────────────


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="safe-fetch",
        description="Docker-isolated URL fetcher + Layer-2 sanitizer for LLM agents.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("url", nargs="?", help="URL to fetch (http or https)")
    parser.add_argument("--version", action="version", version=f"safe-fetch {__version__}")

    install_group = parser.add_argument_group("Claude Code installer")
    mode = install_group.add_mutually_exclusive_group()
    mode.add_argument(
        "--install-claude-hooks",
        action="store_true",
        help="Install hooks, slash commands, and CLAUDE.md snippet into --install-target.",
    )
    mode.add_argument(
        "--uninstall-claude-hooks",
        action="store_true",
        help="Reverse --install-claude-hooks. Leaves untouched user config intact.",
    )
    install_group.add_argument(
        "--install-target",
        type=Path,
        default=Path("~/.claude").expanduser(),
        help="Target dir for install/uninstall (default: ~/.claude).",
    )
    install_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would change without writing.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]

    # `search` is a subcommand with its own parser; route before the
    # top-level parser so the bare `safe-fetch <url>` contract is untouched.
    if args and args[0] == "search":
        return _run_search(args[1:])

    parser = _build_parser()
    try:
        parsed = parser.parse_args(args)
    except SystemExit as e:
        code = int(e.code) if isinstance(e.code, int) else 0
        # argparse calls sys.exit cleanly for --version / --help (code 0)
        # and on parse errors (code 2). Convert both to returns so library
        # callers don't crash the interpreter; only print our usage hint
        # for error cases — never on clean --version / --help exits.
        if code != 0:
            print(USAGE, file=sys.stderr)
        return code

    if parsed.install_claude_hooks:
        return _run_installer(install=True, target=parsed.install_target, dry_run=parsed.dry_run)
    if parsed.uninstall_claude_hooks:
        return _run_installer(install=False, target=parsed.install_target, dry_run=parsed.dry_run)

    if not parsed.url:
        print(USAGE, file=sys.stderr)
        return 2

    err = _validate_url(parsed.url)
    if err:
        print(f"safe-fetch: {err}", file=sys.stderr)
        return 2
    if not _check_docker():
        print(DOCKER_MISSING_MSG, file=sys.stderr)
        return 2
    cmd = _build_docker_command(parsed.url)
    return subprocess.run(cmd, check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
