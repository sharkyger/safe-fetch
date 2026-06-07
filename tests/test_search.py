"""Tests for safe_fetch.search — config + query→URL templating.

The ``search`` subcommand turns a query into a URL by substituting it
into a user-configured template, then runs that URL through the exact
same hardened-container fetch path. This module covers the host-side
pure logic: config load/save (env override > file), template
validation, query validation, and the URL build (with percent-encoding
of the query so it cannot break the envelope or inject extra params).

No search provider is bundled — the config ships empty. ``load_config``
returns ``None`` until the user configures one, and the CLI fails closed
on that.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from safe_fetch import search  # noqa: E402

# ── helpers ──────────────────────────────────────────────────────────


def _clear_env():
    return mock.patch.dict(os.environ, {search.ENV_URL: "", search.ENV_HEADER: ""}, clear=False)


# ── template validation ──────────────────────────────────────────────


class TestTemplateError:
    def test_valid_https_template_passes(self):
        assert search.template_error("https://api.example.com/search?q={query}") is None

    def test_valid_http_template_passes(self):
        assert search.template_error("http://localhost:8888/search?q={query}") is None

    def test_missing_placeholder_rejected(self):
        err = search.template_error("https://api.example.com/search?q=foo")
        assert err is not None and "{query}" in err

    def test_empty_rejected(self):
        assert search.template_error("") is not None

    def test_non_http_scheme_rejected(self):
        err = search.template_error("ftp://example.com/?q={query}")
        assert err is not None and "scheme" in err.lower()

    def test_placeholder_in_host_rejected(self):
        # The query must not be able to control the destination host.
        err = search.template_error("https://{query}/")
        assert err is not None and "host" in err.lower()

    def test_placeholder_as_subdomain_rejected(self):
        err = search.template_error("https://{query}.example.com/?x=1")
        assert err is not None and "host" in err.lower()

    def test_placeholder_in_port_rejected(self):
        err = search.template_error("https://example.com:{query}/s")
        assert err is not None and "host" in err.lower()

    def test_no_host_rejected(self):
        err = search.template_error("https:///search?q={query}")
        assert err is not None and "host" in err.lower()

    def test_control_char_in_template_rejected(self):
        err = search.template_error("https://x.example/s?q={query}\nEvil: 1")
        assert err is not None and "control" in err.lower()

    def test_placeholder_in_fragment_rejected(self):
        # A fragment never reaches the server, so the query would be lost.
        err = search.template_error("https://api.example.com/#q={query}")
        assert err is not None and "fragment" in err.lower()

    def test_placeholder_in_query_with_fragment_present_ok(self):
        assert search.template_error("https://api.example.com/s?q={query}#sec") is None


# ── query validation ─────────────────────────────────────────────────


class TestQueryError:
    def test_normal_query_passes(self):
        assert search.query_error("rust async runtime") is None

    def test_empty_rejected(self):
        assert search.query_error("") is not None

    def test_whitespace_only_rejected(self):
        assert search.query_error("   ") is not None

    def test_control_char_rejected(self):
        err = search.query_error("evil\nLocation: x")
        assert err is not None and "control" in err.lower()

    def test_del_and_c1_controls_rejected(self):
        # DEL (0x7f) and C1 (0x80-0x9f) are control chars too.
        assert search.query_error("a\x7fb") is not None
        assert search.query_error("a\x85b") is not None

    def test_printable_unicode_allowed(self):
        # Accented Latin (>= 0xA0) must NOT be treated as a control char.
        assert search.query_error("café münchen") is None


# ── URL building (percent-encoding is the envelope-safety invariant) ──


class TestBuildSearchUrl:
    def test_spaces_percent_encoded(self):
        url = search.build_search_url("https://x.example/s?q={query}", "rust async")
        assert url == "https://x.example/s?q=rust%20async"

    def test_ampersand_encoded_so_no_param_injection(self):
        # A raw & would smuggle an extra query param into the provider call;
        # both & and = must be percent-encoded into the single q= value.
        url = search.build_search_url("https://x.example/s?q={query}", "a&admin=1")
        assert url == "https://x.example/s?q=a%26admin%3D1"
        assert "&admin=1" not in url

    def test_angle_brackets_and_quotes_encoded(self):
        # These are the envelope-breakout metacharacters; after encoding
        # none of them survive raw into the URL.
        url = search.build_search_url("https://x.example/s?q={query}", '"><UNTRUSTED-WEB>')
        for ch in ('"', "<", ">"):
            assert ch not in url

    def test_placeholder_fully_replaced(self):
        url = search.build_search_url("https://x.example/s?q={query}", "hi")
        assert "{query}" not in url


# ── config load: env override > file, fail-closed when empty ─────────


class TestLoadConfig:
    def test_returns_none_when_nothing_configured(self, tmp_path, monkeypatch):
        monkeypatch.setattr(search, "config_path", lambda: tmp_path / "search.json")
        with _clear_env():
            assert search.load_config() is None

    def test_loads_from_file(self, tmp_path, monkeypatch):
        cfg = tmp_path / "search.json"
        cfg.write_text(json.dumps({"url_template": "https://x.example/s?q={query}"}))
        monkeypatch.setattr(search, "config_path", lambda: cfg)
        with _clear_env():
            loaded = search.load_config()
        assert loaded is not None
        assert loaded.url_template == "https://x.example/s?q={query}"
        assert loaded.auth_header is None

    def test_file_auth_header_loaded(self, tmp_path, monkeypatch):
        cfg = tmp_path / "search.json"
        cfg.write_text(
            json.dumps(
                {
                    "url_template": "https://x.example/s?q={query}",
                    "auth_header": "X-Subscription-Token: secret",
                }
            )
        )
        monkeypatch.setattr(search, "config_path", lambda: cfg)
        with _clear_env():
            loaded = search.load_config()
        assert loaded.auth_header == "X-Subscription-Token: secret"

    def test_env_url_overrides_file(self, tmp_path, monkeypatch):
        cfg = tmp_path / "search.json"
        cfg.write_text(json.dumps({"url_template": "https://file.example/s?q={query}"}))
        monkeypatch.setattr(search, "config_path", lambda: cfg)
        monkeypatch.setenv(search.ENV_URL, "https://env.example/s?q={query}")
        monkeypatch.setenv(search.ENV_HEADER, "Authorization: Bearer t")
        loaded = search.load_config()
        assert loaded.url_template == "https://env.example/s?q={query}"
        assert loaded.auth_header == "Authorization: Bearer t"

    def test_env_header_supplements_file_url(self, tmp_path, monkeypatch):
        # A user may keep the URL in the file and the secret in the env.
        cfg = tmp_path / "search.json"
        cfg.write_text(json.dumps({"url_template": "https://file.example/s?q={query}"}))
        monkeypatch.setattr(search, "config_path", lambda: cfg)
        monkeypatch.delenv(search.ENV_URL, raising=False)
        monkeypatch.setenv(search.ENV_HEADER, "Authorization: Bearer env-secret")
        loaded = search.load_config()
        assert loaded.url_template == "https://file.example/s?q={query}"
        assert loaded.auth_header == "Authorization: Bearer env-secret"

    def test_env_header_overrides_file_header(self, tmp_path, monkeypatch):
        cfg = tmp_path / "search.json"
        cfg.write_text(json.dumps({"url_template": "https://file.example/s?q={query}", "auth_header": "X-Old: stale"}))
        monkeypatch.setattr(search, "config_path", lambda: cfg)
        monkeypatch.delenv(search.ENV_URL, raising=False)
        monkeypatch.setenv(search.ENV_HEADER, "X-New: fresh")
        assert search.load_config().auth_header == "X-New: fresh"

    def test_malformed_json_raises(self, tmp_path, monkeypatch):
        cfg = tmp_path / "search.json"
        cfg.write_text("{ not json ")
        monkeypatch.setattr(search, "config_path", lambda: cfg)
        with _clear_env(), pytest.raises(search.SearchConfigError):
            search.load_config()

    def test_non_string_url_template_raises(self, tmp_path, monkeypatch):
        cfg = tmp_path / "search.json"
        cfg.write_text(json.dumps({"url_template": 123}))
        monkeypatch.setattr(search, "config_path", lambda: cfg)
        with _clear_env(), pytest.raises(search.SearchConfigError, match="must be a string"):
            search.load_config()

    def test_non_string_auth_header_raises(self, tmp_path, monkeypatch):
        cfg = tmp_path / "search.json"
        cfg.write_text(json.dumps({"url_template": "https://x.example/s?q={query}", "auth_header": 5}))
        monkeypatch.setattr(search, "config_path", lambda: cfg)
        with _clear_env(), pytest.raises(search.SearchConfigError, match="must be a string"):
            search.load_config()

    def test_non_dict_json_raises_object_error(self, tmp_path, monkeypatch):
        cfg = tmp_path / "search.json"
        cfg.write_text("42")
        monkeypatch.setattr(search, "config_path", lambda: cfg)
        with _clear_env(), pytest.raises(search.SearchConfigError, match="JSON object"):
            search.load_config()

    def test_file_missing_url_template_raises(self, tmp_path, monkeypatch):
        cfg = tmp_path / "search.json"
        cfg.write_text(json.dumps({"auth_header": "Authorization: Bearer t"}))
        monkeypatch.setattr(search, "config_path", lambda: cfg)
        with _clear_env(), pytest.raises(search.SearchConfigError):
            search.load_config()


# ── config save: atomic, 0600 ────────────────────────────────────────


class TestSaveConfig:
    def test_writes_file_with_owner_only_perms(self, tmp_path, monkeypatch):
        cfg = tmp_path / "sub" / "search.json"
        monkeypatch.setattr(search, "config_path", lambda: cfg)
        search.save_config(search.SearchConfig(url_template="https://x.example/s?q={query}"))
        assert cfg.exists()
        mode = stat.S_IMODE(cfg.stat().st_mode)
        assert mode == 0o600, f"expected 0o600, got {oct(mode)}"

    def test_roundtrip_load(self, tmp_path, monkeypatch):
        cfg = tmp_path / "search.json"
        monkeypatch.setattr(search, "config_path", lambda: cfg)
        original = search.SearchConfig(
            url_template="https://x.example/s?q={query}",
            auth_header="X-Key: abc",
        )
        search.save_config(original)
        with _clear_env():
            loaded = search.load_config()
        assert loaded.url_template == original.url_template
        assert loaded.auth_header == original.auth_header

    def test_dry_run_writes_nothing(self, tmp_path, monkeypatch):
        cfg = tmp_path / "search.json"
        monkeypatch.setattr(search, "config_path", lambda: cfg)
        search.save_config(search.SearchConfig(url_template="https://x.example/s?q={query}"), dry_run=True)
        assert not cfg.exists()

    def test_secret_not_in_config_file_when_no_auth(self, tmp_path, monkeypatch):
        cfg = tmp_path / "search.json"
        monkeypatch.setattr(search, "config_path", lambda: cfg)
        search.save_config(search.SearchConfig(url_template="https://x.example/s?q={query}"))
        data = json.loads(cfg.read_text())
        assert "auth_header" not in data or data["auth_header"] in (None, "")


# ── config path honors XDG ───────────────────────────────────────────


class TestConfigPath:
    def test_honors_xdg_config_home(self, tmp_path, monkeypatch):
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
        p = search.config_path()
        assert p == tmp_path / "safe-fetch" / "search.json"

    def test_falls_back_to_dot_config(self, monkeypatch):
        monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
        p = search.config_path()
        assert p.name == "search.json"
        assert p.parent.name == "safe-fetch"
        assert ".config" in str(p)
