"""The Dockerfile's inline pins must match pyproject.toml, exactly.

Why this file exists
--------------------
``pyproject.toml`` states the invariant in a comment:

    Exact-pin to match docker/Dockerfile so the host-side install and the
    in-container install resolve to the same parsed-tree behavior.
    Dependabot tracks bumps; manual PRs update Dockerfile in lockstep.

The second sentence is the problem. Dependabot bumps ``pyproject.toml`` and
**cannot reach an inline install pin inside a Dockerfile** — no ecosystem
covers it. (This repo has no ``docker`` ecosystem entry either, so the base
image is untracked as well; that is a separate gap.) The manifest moves, the
image does not, and nothing says so.

That happened on 2026-08-29: PR #19 bumped lxml in ``pyproject.toml`` and
merged green, leaving ``docker/Dockerfile`` a version behind. Found by reading
the file, not by any gate.

A comment asking humans to remember is not a mechanism. This is the mechanism:
a desync fails the suite instead of shipping silently.

The postscript is the more useful lesson. Review then asked whether lxml was
used at all — it was not. ``sanitizer.py`` parses with ``html.parser``; nothing
imported lxml, ever. It had been pinned, CVE-bumped twice and had dragged a
native build toolchain into the image, and this very test had been written to
protect its version. So a pin can be perfectly synchronised and still be
pointless. ``test_lxml_is_not_reintroduced`` keeps that from quietly returning.

What the file guards now is real: ``beautifulsoup4`` and ``soupsieve``, both
imported, both pure Python. The image deliberately does NOT install the package
itself (that would drag the CLI into a container built to carry only the
sanitizer), so the inline pins cannot simply be removed — keep them, enforce
them.

Two fail-opens in the first version were caught by review and are now
regression-tested: pins were scanned across the whole Dockerfile with
last-match-wins (so a comment could mask a stale pin), and the deps block ran
past the ``[project]`` table (so a dev dependency could parse as a runtime pin).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = REPO_ROOT / "docker" / "Dockerfile"
PYPROJECT = REPO_ROOT / "pyproject.toml"

# "name==version" inside single quotes.
_DOCKER_PIN = re.compile(r"'([A-Za-z0-9_.-]+)==([0-9][0-9A-Za-z.+-]*)'")
# The install command plus any backslash continuations. Scanning the WHOLE
# Dockerfile was a fail-open: `finditer` + a dict comprehension is last-match-
# wins, so leaving the real pin stale and adding a comment further down that
# quotes the correct version made the test pass on a desynced image. In a file
# whose thesis is "a comment is not a mechanism", the mechanism was defeatable
# by a comment. Reproduced before this fix; guarded by
# test_a_trailing_comment_cannot_mask_a_stale_pin.
_INSTALL_CMD = re.compile(r"^[^\n]*\bpip install\b(?:[^\n]*\\\n)*[^\n]*", re.M)

# "name==version" inside the pyproject [project] dependencies list.
# Regex rather than tomllib on purpose: tomllib is 3.11+ and this repo's CI
# still tests 3.10 — a guard that cannot run on a supported interpreter is
# worse than no guard.
_PYPROJECT_PIN = re.compile(r'"([A-Za-z0-9_.-]+)==([0-9][0-9A-Za-z.+-]*)"')
# The [project] table, up to the next table header. Anchoring here is what
# keeps [project.optional-dependencies] out: the previous pattern ran to the
# next `]` at column 0, which for an inline deps list — or an indented closing
# bracket — swallowed the dev-dependency table and parsed e.g. ruff==0.6.9 as
# a runtime pin. Reproduced before this fix.
_PROJECT_TABLE = re.compile(r"^\[project\]\s*$(.*?)(?=^\[|\Z)", re.M | re.S)
_DEPS_BLOCK = re.compile(r"^dependencies\s*=\s*\[(.*?)\]", re.M | re.S)


def _dockerfile_pins() -> dict[str, str]:
    """Pins from the install command only, and duplicates are an error."""
    text = DOCKERFILE.read_text(encoding="utf-8")
    pins: dict[str, str] = {}
    for cmd in _INSTALL_CMD.findall(text):
        for m in _DOCKER_PIN.finditer(cmd):
            name, ver = m.group(1).lower(), m.group(2)
            if name in pins and pins[name] != ver:
                raise AssertionError(
                    f"docker/Dockerfile pins {name} twice with different versions: {pins[name]} and {ver}"
                )
            pins[name] = ver
    return pins


def _pyproject_pins() -> dict[str, str]:
    """Runtime pins from the [project] table's dependencies list only.

    Scoped to that table so [project.optional-dependencies] (pytest, ruff,
    mypy) cannot leak in — those are dev tools, deliberately absent from the
    image, and counting them would demand the image install them.
    """
    table = _PROJECT_TABLE.search(PYPROJECT.read_text(encoding="utf-8"))
    if table is None:
        return {}
    block = _DEPS_BLOCK.search(table.group(1))
    if block is None:
        return {}
    return {m.group(1).lower(): m.group(2) for m in _PYPROJECT_PIN.finditer(block.group(1))}


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


# --------------------------------------------------------------------------
# regressions — both fail-opens below shipped once and were caught by review
# --------------------------------------------------------------------------
def test_a_trailing_comment_cannot_mask_a_stale_pin(tmp_path, monkeypatch):
    """The first version scanned the whole Dockerfile with last-match-wins, so a
    comment quoting the right version hid a stale real pin and the suite went
    green on a desynced image."""
    fake = tmp_path / "Dockerfile"
    fake.write_text(
        "FROM python:3.12-alpine\n"
        "RUN " + "pip inst" + "all --no-cache-dir 'beautifulsoup4==4.15.0' 'soupsieve==1.0.0'\n"
        "# pyproject currently says 'soupsieve==2.9.2'\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(sys.modules[__name__], "DOCKERFILE", fake)
    assert _dockerfile_pins()["soupsieve"] == "1.0.0", "a comment must never outrank the real install line"


def test_optional_dependencies_never_leak_into_runtime_pins(tmp_path, monkeypatch):
    """The first version ran to the next `]` at column 0, so an inline deps list
    or an indented closing bracket swallowed [project.optional-dependencies] and
    parsed a dev tool as a runtime pin."""
    for body in (
        '[project]\ndependencies = ["beautifulsoup4==4.15.0", "soupsieve==2.9.2"]\n\n'
        '[project.optional-dependencies]\ndev = [\n    "ruff==0.6.9",\n]\n',
        '[project]\ndependencies = [\n    "beautifulsoup4==4.15.0",\n    "soupsieve==2.9.2",\n  ]\n\n'
        '[project.optional-dependencies]\ndev = [\n    "ruff==0.6.9",\n]\n',
    ):
        fake = tmp_path / "pyproject.toml"
        fake.write_text(body, encoding="utf-8")
        monkeypatch.setattr(sys.modules[__name__], "PYPROJECT", fake)
        pins = _pyproject_pins()
        assert "ruff" not in pins, f"dev dependency leaked into runtime pins: {sorted(pins)}"
        assert set(pins) == {"beautifulsoup4", "soupsieve"}


def test_lxml_is_not_reintroduced():
    """lxml was carried for months, pinned and CVE-bumped twice, while nothing
    imported it — sanitizer.py parses with html.parser. If it ever returns it
    must return with an import site, not as an unexamined habit."""
    assert "lxml" not in _pyproject_pins(), "lxml is back in pyproject — is it actually imported now?"
    assert "lxml" not in _dockerfile_pins(), "lxml is back in the image — is it actually imported now?"
