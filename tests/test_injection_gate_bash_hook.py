"""Regression tests for ``injection-gate-bash.sh``.

The hook reads a JSON tool_input event on stdin and exits:
  - 0 → allow (host on allowlist, or not a curl/wget invocation)
  - 2 → block (reroute to safe-fetch)

Tests run the actual shell script via subprocess against the source-of-truth
copy in ``src/safe_fetch/data/hooks/``.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

HOOK = Path(__file__).parent.parent / "src" / "safe_fetch" / "data" / "hooks" / "injection-gate-bash.sh"


def _run(command: str, tool: str = "Bash") -> tuple[int, str, str]:
    """Invoke the hook with a Bash tool_use event for ``command``."""
    payload = {"tool_name": tool, "tool_input": {"command": command}}
    proc = subprocess.run(
        ["bash", str(HOOK)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=10,
    )
    return proc.returncode, proc.stdout, proc.stderr


# ── Stage 0: marker-dir block ─────────────────────────────────────────


class TestStage0MarkerDir:
    def test_literal_marker_path_blocked(self):
        rc, _, err = _run("touch /tmp/.claude-injection-gate/rule-deadbeef")
        assert rc == 2
        assert "injection-gate marker" in err


# ── Stage 1: command boundary ─────────────────────────────────────────


class TestStage1CommandBoundary:
    def test_non_bash_tool_passes(self):
        rc, _, _ = _run("curl https://evil.com/", tool="Write")
        assert rc == 0

    def test_man_curl_passes(self):
        # `man curl` is preceded by a non-separator → curl is not at a
        # command boundary.
        rc, _, _ = _run("man curl")
        assert rc == 0

    def test_curl_version_passes(self):
        # No URL token → not a fetch.
        rc, _, _ = _run("curl --version")
        assert rc == 0


# ── Stage 2: URL extraction + allowlist ───────────────────────────────


class TestStage2Allowlist:
    def test_allowlisted_anthropic_passes(self):
        rc, _, _ = _run("curl https://anthropic.com/")
        assert rc == 0

    def test_allowlisted_docs_anthropic_passes(self):
        rc, _, _ = _run("curl https://docs.anthropic.com/en/foo")
        assert rc == 0

    def test_non_allowlisted_evil_blocked(self):
        rc, _, err = _run("curl https://evil.com/")
        assert rc == 2
        assert "evil.com" in err or "non-allowlisted" in err

    def test_wget_blocked(self):
        rc, _, err = _run("wget https://example.com/")
        assert rc == 2
        assert "safe-fetch" in err


# ── Regression: URL-userinfo bypass (CR CRITICAL F-1) ─────────────────


class TestUserinfoBypass:
    """`curl https://anthropic.com@evil.com/` must NOT pass the allowlist.

    The HTTP authority `userinfo@host` puts `anthropic.com` in the userinfo
    position and `evil.com` is the real host. The hook used to extract
    `anthropic.com` as HOST and approve the request — letting curl actually
    hit `evil.com`. Fix: strip userinfo from HOST before matching.
    """

    def test_scheme_prefixed_userinfo_blocked(self):
        rc, _, err = _run("curl https://anthropic.com@evil.com/")
        assert rc == 2, f"userinfo bypass slipped: stderr={err!r}"
        # The actual host is evil.com — the block message should reflect that,
        # not anthropic.com.
        assert "anthropic.com" not in err.split("Host:")[1].split("\n")[0] if "Host:" in err else True

    def test_scheme_prefixed_userinfo_with_path_blocked(self):
        rc, _, err = _run("curl https://anthropic.com@evil.com/path/to/page")
        assert rc == 2, f"userinfo+path bypass slipped: stderr={err!r}"

    def test_userinfo_with_password_blocked(self):
        rc, _, err = _run("curl 'https://anthropic.com:hunter2@evil.com/'")
        assert rc == 2, f"userinfo:password bypass slipped: stderr={err!r}"

    def test_scheme_less_userinfo_blocked(self):
        rc, _, err = _run("curl anthropic.com@evil.com/")
        assert rc == 2, f"scheme-less userinfo bypass slipped: stderr={err!r}"

    def test_empty_password_userinfo_blocked(self):
        rc, _, err = _run("curl 'https://anthropic.com:@evil.com/'")
        assert rc == 2, f"empty-password userinfo bypass slipped: stderr={err!r}"


# ── Regression: Stage 2 prefers scheme-prefixed URL (CR MAJOR F-3) ────


class TestStage2PrefersSchemePrefixedUrl:
    """When the command contains both an extraneous host-shaped token and a
    real ``https://...`` URL, the hook used to match the first host-shaped
    token via a non-greedy first-match. With the fix it must prefer the
    scheme-prefixed URL.
    """

    def test_output_path_does_not_shadow_url(self):
        # `-o /tmp/file.bin` has `file.bin` which contains a dot but isn't a
        # host. The actual URL is example.com.
        rc, _, err = _run("curl -o /tmp/file.bin https://example.com/page")
        assert rc == 2, f"expected block for example.com, got rc={rc} stderr={err!r}"
        assert "example.com" in err

    def test_flag_value_doesnt_match_as_host(self):
        rc, _, _ = _run("curl --version")
        assert rc == 0
