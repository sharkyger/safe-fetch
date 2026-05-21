"""Host-side CLI for safe-fetch.

Pre-flight checks Docker, validates the URL, and invokes the
``safe-fetch:latest`` image with the locked-down ``docker run`` flags
documented in ``docs/roadmaps/injection-gate-pillar.md`` Part 2.

Every flag in ``DOCKER_FLAGS`` is asserted by ``tests/test_safe_fetch_cli.py``.
A missing or relaxed flag is a security regression — change the test
deliberately if you intend to alter the contract.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from urllib.parse import urlparse

IMAGE_NAME = "safe-fetch:latest"
USAGE = "Usage: safe-fetch <url>"


# Locked-down docker-run flag set. See scope Part 2 (Layer 1) for the
# rationale on each flag. Order matches the human-readable explanation
# in the plan and review notes.
DOCKER_FLAGS = [
    "--rm",
    "-i",
    "--network=bridge",
    "--read-only",
    "--tmpfs",
    "/tmp:rw,size=8m,noexec,nosuid",  # noqa: S108 — docker tmpfs spec, not a host-side temp path
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


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    if len(args) != 1:
        print(USAGE, file=sys.stderr)
        return 2
    url = args[0]
    err = _validate_url(url)
    if err:
        print(f"safe-fetch: {err}", file=sys.stderr)
        return 2
    if not _check_docker():
        print(DOCKER_MISSING_MSG, file=sys.stderr)
        return 2
    cmd = _build_docker_command(url)
    return subprocess.run(cmd, check=False).returncode


if __name__ == "__main__":
    sys.exit(main())
