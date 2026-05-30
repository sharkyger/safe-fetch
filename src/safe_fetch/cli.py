"""Host-side CLI for safe-fetch.

Two modes:

  ``safe-fetch <url>``
      Pre-flight Docker, validate the URL, run the locked-down
      ``safe-fetch:latest`` image, stream sanitized stdout back.

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
import shutil
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse

from safe_fetch import __version__

IMAGE_NAME = "safe-fetch:latest"
USAGE = (
    "Usage: safe-fetch <url>\n"
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


def _build_docker_command(url: str, image: str = IMAGE_NAME) -> list[str]:
    """Pure: assemble the locked-down docker-run argv for the given URL.

    The URL is the LAST argv entry. Anything before the image name is
    flags interpreted by docker itself; positioning the URL after the
    image makes accidental flag-injection impossible even if a future
    refactor mishandles validation.
    """
    return ["docker", "run", *DOCKER_FLAGS, image, url]


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
