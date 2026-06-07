"""Tests for the ``safe-fetch search --setup`` wizard.

The wizard is the easy front door: it interactively collects a search
URL template and an optional auth header (read without echo), optionally
runs a real test search, and writes the config file with owner-only
permissions. I/O is injected (``input_fn`` / ``getpass_fn``) so the
wizard is unit-testable without a TTY or Docker.
"""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from safe_fetch import search, search_setup  # noqa: E402


def _inputs(*values):
    it = iter(values)
    return lambda prompt="": next(it)


class TestWizard:
    def test_happy_path_saves_config(self, tmp_path, monkeypatch):
        cfg = tmp_path / "search.json"
        monkeypatch.setattr(search, "config_path", lambda: cfg)
        rc = search_setup.run_setup(
            input_fn=_inputs("https://api.example.com/s?q={query}", "n"),
            getpass_fn=_inputs(""),
        )
        assert rc == 0
        data = json.loads(cfg.read_text())
        assert data["url_template"] == "https://api.example.com/s?q={query}"
        assert data.get("auth_header") in (None, "")

    def test_config_written_owner_only(self, tmp_path, monkeypatch):
        cfg = tmp_path / "search.json"
        monkeypatch.setattr(search, "config_path", lambda: cfg)
        search_setup.run_setup(
            input_fn=_inputs("https://api.example.com/s?q={query}", "n"),
            getpass_fn=_inputs(""),
        )
        assert stat.S_IMODE(cfg.stat().st_mode) == 0o600

    def test_auth_header_captured_via_getpass(self, tmp_path, monkeypatch):
        cfg = tmp_path / "search.json"
        monkeypatch.setattr(search, "config_path", lambda: cfg)
        search_setup.run_setup(
            input_fn=_inputs("https://api.example.com/s?q={query}", "n"),
            getpass_fn=_inputs("X-Subscription-Token: secret-value"),
        )
        data = json.loads(cfg.read_text())
        assert data["auth_header"] == "X-Subscription-Token: secret-value"

    def test_invalid_template_reprompts(self, tmp_path, monkeypatch):
        cfg = tmp_path / "search.json"
        monkeypatch.setattr(search, "config_path", lambda: cfg)
        rc = search_setup.run_setup(
            # first answer lacks {query} → wizard must re-prompt
            input_fn=_inputs("https://api.example.com/s?q=foo", "https://api.example.com/s?q={query}", "n"),
            getpass_fn=_inputs(""),
        )
        assert rc == 0
        assert json.loads(cfg.read_text())["url_template"] == "https://api.example.com/s?q={query}"

    def test_dry_run_writes_nothing(self, tmp_path, monkeypatch):
        cfg = tmp_path / "search.json"
        monkeypatch.setattr(search, "config_path", lambda: cfg)
        rc = search_setup.run_setup(
            input_fn=_inputs("https://api.example.com/s?q={query}", "n"),
            getpass_fn=_inputs(""),
            dry_run=True,
        )
        assert rc == 0
        assert not cfg.exists()

    def test_test_search_invoked_when_requested(self, tmp_path, monkeypatch):
        cfg = tmp_path / "search.json"
        monkeypatch.setattr(search, "config_path", lambda: cfg)
        calls = {}

        def fake_test(url, auth_header):
            calls["url"] = url
            calls["auth"] = auth_header
            return 0

        search_setup.run_setup(
            input_fn=_inputs("https://api.example.com/s?q={query}", "y"),
            getpass_fn=_inputs("Authorization: Bearer t"),
            run_test_fn=fake_test,
        )
        # The test search must use a concrete (query-substituted) URL, never
        # the raw template, and must pass the auth header through.
        assert "{query}" not in calls["url"]
        assert calls["auth"] == "Authorization: Bearer t"
