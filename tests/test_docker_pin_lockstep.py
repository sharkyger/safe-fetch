"""The Dockerfile's inline pins must match pyproject.toml, exactly.

Why this file exists
--------------------
``pyproject.toml`` states the invariant in a comment:

    Exact-pin to match docker/Dockerfile so the host-side install and the
    in-container install resolve to the same parsed-tree behavior.
    Dependabot tracks bumps; manual PRs update Dockerfile in lockstep.

The second sentence is the problem. Dependabot bumps ``pyproject.toml`` and
**cannot reach an inline ``pip install`` pin inside a Dockerfile** — no
ecosystem covers it, and the ``docker`` ecosystem only tracks the base image.
So the manifest moves, the image does not, and nothing anywhere says so.

That is exactly what happened on 2026-08-29: PR #19 bumped lxml 6.1.1 -> 6.1.2
in ``pyproject.toml`` and merged green, leaving ``docker/Dockerfile`` pinned at
6.1.1. The host install and the container install were then parsing with
different lxml versions — in a tool whose entire premise is that both produce
byte-identical sanitized output. It was found by reading the file, not by any
gate.

A comment asking humans to remember is not a mechanism. This is the mechanism:
a desync now fails the test suite instead of shipping silently.

Note the image deliberately does NOT ``pip install .`` (that would drag the CLI
into a container built to carry only the sanitizer), so the inline pin cannot
simply be removed. Hence: keep the pin, enforce it.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = REPO_ROOT / "docker" / "Dockerfile"
PYPROJECT = REPO_ROOT / "pyproject.toml"

# "name==version" inside single quotes on the Dockerfile's pip install line.
_DOCKER_PIN = re.compile(r"'([A-Za-z0-9_.-]+)==([0-9][0-9A-Za-z.+-]*)'")
# "name==version" as a pyproject dependency entry.
_PYPROJECT_PIN = re.compile(r"^([A-Za-z0-9_.-]+)==([0-9][0-9A-Za-z.+-]*)$")


def _dockerfile_pins() -> dict[str, str]:
    return {m.group(1).lower(): m.group(2) for m in _DOCKER_PIN.finditer(DOCKERFILE.read_text(encoding="utf-8"))}


def _pyproject_pins() -> dict[str, str]:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    pins: dict[str, str] = {}
    for entry in data["project"]["dependencies"]:
        m = _PYPROJECT_PIN.match(entry.strip())
        if m:
            pins[m.group(1).lower()] = m.group(2)
    return pins


def test_fixtures_are_actually_parsed():
    """Guard the guard: if either parser silently returns {}, every assertion
    below passes vacuously and this file becomes decorative — the fail-open
    shape these repos keep shipping."""
    assert _dockerfile_pins(), "parsed NO pins out of docker/Dockerfile"
    assert _pyproject_pins(), "parsed NO pins out of pyproject.toml"


@pytest.mark.parametrize("package", sorted(_pyproject_pins()))
def test_dockerfile_pin_matches_pyproject(package: str):
    """Every runtime dependency pinned in pyproject must be pinned identically
    in the image, or the two installs parse differently."""
    docker_pins = _dockerfile_pins()
    expected = _pyproject_pins()[package]
    assert package in docker_pins, (
        f"{package}=={expected} is pinned in pyproject.toml but absent from docker/Dockerfile — "
        "the image will resolve it differently or not install it at all"
    )
    assert docker_pins[package] == expected, (
        f"PIN DESYNC: {package} is {expected} in pyproject.toml but "
        f"{docker_pins[package]} in docker/Dockerfile. Dependabot bumps the manifest and cannot "
        "reach the Dockerfile — update the Dockerfile in the same PR."
    )


def test_no_unpinned_extra_packages_in_the_image():
    """The image must not carry a runtime package the manifest does not declare;
    that package would never be CVE-tracked by Dependabot."""
    extra = set(_dockerfile_pins()) - set(_pyproject_pins())
    assert not extra, (
        f"docker/Dockerfile installs {sorted(extra)} which pyproject.toml does not declare — "
        "Dependabot tracks the manifest, so these would never be scanned"
    )
