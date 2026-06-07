"""Tests for docker/entrypoint.py — the in-container fetcher.

The module is normally executed inside the safe-fetch container with
``/app/entrypoint.py``; on the host we add ``docker/`` to sys.path so
import works for unit testing. The sibling ``sanitizer.py`` is in the
same directory so the relative import resolves.
"""

from __future__ import annotations

import sys
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

import pytest

REPO_ROOT = Path(__file__).parent.parent
# Inside the safe-fetch container both ``entrypoint.py`` and
# ``sanitizer.py`` live in /app/. On the host they live in ``docker/``
# and ``src/safe_fetch/`` respectively, so we add both directories to
# sys.path before importing.
sys.path.insert(0, str(REPO_ROOT / "src" / "safe_fetch"))
sys.path.insert(0, str(REPO_ROOT / "docker"))

import entrypoint  # noqa: E402  # isort: skip


# ── _validate ─────────────────────────────────────────────────────────


class TestValidate:
    def test_https_passes(self):
        entrypoint._validate("https://example.com/")  # no exit

    def test_http_passes(self):
        entrypoint._validate("http://example.com/")

    def test_file_scheme_exits(self):
        with pytest.raises(SystemExit) as e:
            entrypoint._validate("file:///etc/passwd")
        assert e.value.code == 2

    def test_javascript_scheme_exits(self):
        with pytest.raises(SystemExit) as e:
            entrypoint._validate("javascript:alert(1)")
        assert e.value.code == 2

    def test_no_host_exits(self):
        with pytest.raises(SystemExit):
            entrypoint._validate("https:///path")


# ── ValidatingRedirectHandler ─────────────────────────────────────────


class TestValidatingRedirectHandler:
    """Each redirect hop must be re-validated.

    The default urllib HTTPRedirectHandler restricts redirect schemes to
    http/https/ftp but does not re-run our own host validation
    (``_validate``). Without re-validation a 30x response could redirect
    a sanctioned http/https request into, say, a host-less URL or a
    scheme we explicitly disallow.

    The fix installs a ``_ValidatingRedirectHandler`` that calls
    ``_validate(newurl)`` on every hop. Validation failure converts to
    an ``HTTPError`` so the caller's existing error handling reports it.
    """

    def _handler(self):
        return entrypoint._ValidatingRedirectHandler()

    def _fake_args(self, newurl: str):
        # The shape redirect_request expects:
        #   redirect_request(req, fp, code, msg, headers, newurl)
        req = urllib.request.Request("https://origin.example/")
        fp = mock.MagicMock()
        headers = mock.MagicMock()
        return req, fp, 302, "Found", headers, newurl

    def test_https_redirect_passes(self):
        h = self._handler()
        args = self._fake_args("https://other.example/page")
        # Should return a Request object (delegated to super()).
        result = h.redirect_request(*args)
        assert isinstance(result, urllib.request.Request)
        assert result.full_url == "https://other.example/page"

    def test_http_redirect_passes(self):
        h = self._handler()
        result = h.redirect_request(*self._fake_args("http://other.example/page"))
        assert isinstance(result, urllib.request.Request)

    def test_file_scheme_redirect_blocked(self):
        h = self._handler()
        with pytest.raises(urllib.error.HTTPError) as exc:
            h.redirect_request(*self._fake_args("file:///etc/passwd"))
        assert exc.value.code == 403

    def test_javascript_scheme_redirect_blocked(self):
        h = self._handler()
        with pytest.raises(urllib.error.HTTPError) as exc:
            h.redirect_request(*self._fake_args("javascript:alert(1)"))
        assert exc.value.code == 403

    def test_data_scheme_redirect_blocked(self):
        h = self._handler()
        with pytest.raises(urllib.error.HTTPError) as exc:
            h.redirect_request(*self._fake_args("data:text/plain,hi"))
        assert exc.value.code == 403

    def test_hostless_redirect_blocked(self):
        # The commit message lists "empty host" as a primary threat the
        # handler exists to close. Cover it explicitly.
        h = self._handler()
        with pytest.raises(urllib.error.HTTPError) as exc:
            h.redirect_request(*self._fake_args("https:///path"))
        assert exc.value.code == 403


# ── _fetch wiring ─────────────────────────────────────────────────────


class TestUserAgentMatchesPackageVersion:
    """The in-container USER_AGENT string must include the same version
    string that `safe_fetch.__version__` reports.

    The container image bundles `entrypoint.py` but not `safe_fetch.__init__`,
    so the version is kept in sync manually; this test catches drift.
    """

    def test_user_agent_contains_package_version(self):
        from safe_fetch import __version__

        assert __version__ in entrypoint.USER_AGENT, (
            f"USER_AGENT={entrypoint.USER_AGENT!r} does not include __version__={__version__!r}"
        )

    def test_user_agent_starts_with_product_name(self):
        assert entrypoint.USER_AGENT.startswith("safe-fetch/")


class TestFetchUsesValidatingHandler:
    """``_fetch`` must build an opener that includes
    ``_ValidatingRedirectHandler``.

    Asserting via a mock on ``build_opener`` keeps the test fast (no
    real HTTP) and verifies the wiring is correct.
    """

    def test_fetch_installs_validating_redirect_handler(self):
        with (
            mock.patch.object(entrypoint.urllib.request, "build_opener") as build,
            mock.patch.object(entrypoint.urllib.request, "urlopen") as _,
        ):
            opener = mock.MagicMock()
            opener.open.return_value.__enter__.return_value.read.return_value = b"<html></html>"
            build.return_value = opener
            entrypoint._fetch("https://example.com/")
        build.assert_called_once()
        installed = build.call_args.args
        assert any(isinstance(h, entrypoint._ValidatingRedirectHandler) for h in installed), (
            f"expected a _ValidatingRedirectHandler in build_opener args, got {installed!r}"
        )


# ── optional search auth header ───────────────────────────────────────


class TestSearchHeaderParsing:
    """``SAFE_FETCH_SEARCH_HEADER`` lets the host forward a search-provider
    auth header into the container's fetch. It is parsed defensively:
    blank/colon-less values are ignored, and control characters (CR/LF)
    are stripped so a crafted value cannot inject extra request headers.
    """

    def _env(self, value):
        return mock.patch.dict("os.environ", {"SAFE_FETCH_SEARCH_HEADER": value}, clear=False)

    def _unset(self):
        env = {k: v for k, v in __import__("os").environ.items() if k != "SAFE_FETCH_SEARCH_HEADER"}
        return mock.patch.dict("os.environ", env, clear=True)

    def test_unset_returns_none(self):
        with self._unset():
            assert entrypoint._search_header() is None

    def test_blank_returns_none(self):
        with self._env("   "):
            assert entrypoint._search_header() is None

    def test_no_colon_dies_loud(self):
        # A non-blank but unparseable header is a misconfig — fail loud,
        # don't silently send the request unauthenticated.
        with self._env("not a header"), pytest.raises(SystemExit) as e:
            entrypoint._search_header()
        assert e.value.code == 2

    def test_empty_name_dies_loud(self):
        with self._env(": secret-only-no-name"), pytest.raises(SystemExit) as e:
            entrypoint._search_header()
        assert e.value.code == 2

    def test_parsed_and_stripped(self):
        with self._env("  X-Subscription-Token :  secret-value "):
            assert entrypoint._search_header() == ("X-Subscription-Token", "secret-value")

    def test_crlf_stripped_no_header_injection(self):
        with self._env("Authorization: Bearer t\r\nX-Injected: evil"):
            name, value = entrypoint._search_header()
            assert "\r" not in value and "\n" not in value
            assert "X-Injected" not in value

    def test_unicode_line_separator_truncates(self):
        # splitlines() also breaks on U+2028 / NEL etc., so an injected
        # trailing line via an exotic separator is dropped too.
        with self._env("Authorization: Bearer t" + "\u2028" + "X-Injected: evil"):
            _, value = entrypoint._search_header()
            assert "X-Injected" not in value

    def test_del_control_char_stripped(self):
        # DEL (0x7f) is not a line separator but must be stripped from the value.
        with self._env("X-Tok: ab\x7fcd"):
            name, value = entrypoint._search_header()
            assert name == "X-Tok"
            assert value == "abcd"


class TestFetchSendsSearchHeader:
    def _run_fetch(self):
        with (
            mock.patch.object(entrypoint.urllib.request, "build_opener") as build,
            mock.patch.object(entrypoint.urllib.request, "urlopen"),
        ):
            opener = mock.MagicMock()
            opener.open.return_value.__enter__.return_value.read.return_value = b"<html></html>"
            build.return_value = opener
            entrypoint._fetch("https://example.com/")
        return opener.open.call_args.args[0]

    def test_header_added_to_request_when_set(self):
        with mock.patch.dict("os.environ", {"SAFE_FETCH_SEARCH_HEADER": "Authorization: Bearer t"}, clear=False):
            req = self._run_fetch()
        assert req.get_header("Authorization") == "Bearer t"

    def test_no_header_when_unset(self):
        env = {k: v for k, v in __import__("os").environ.items() if k != "SAFE_FETCH_SEARCH_HEADER"}
        with mock.patch.dict("os.environ", env, clear=True):
            req = self._run_fetch()
        assert req.get_header("Authorization") is None


# ── credential-handling hardening (cleartext + redirects) ─────────────


class TestLoopbackDetection:
    def test_localhost(self):
        assert entrypoint._host_is_loopback("localhost:8080") is True

    def test_127(self):
        assert entrypoint._host_is_loopback("127.0.0.1") is True

    def test_ipv6_loopback(self):
        assert entrypoint._host_is_loopback("[::1]:443") is True

    def test_remote_host(self):
        assert entrypoint._host_is_loopback("api.example.com") is False

    def test_public_ip(self):
        assert entrypoint._host_is_loopback("8.8.8.8") is False


class TestCleartextCredentialGuard:
    """An auth header must not travel over plaintext http (loopback excepted)."""

    def _fetch_capture(self, url):
        with (
            mock.patch.object(entrypoint.urllib.request, "build_opener") as build,
            mock.patch.object(entrypoint.urllib.request, "urlopen"),
        ):
            opener = mock.MagicMock()
            opener.open.return_value.__enter__.return_value.read.return_value = b"<html></html>"
            build.return_value = opener
            entrypoint._fetch(url)
            return opener.open.call_args.args[0]

    def _auth_env(self):
        return mock.patch.dict("os.environ", {"SAFE_FETCH_SEARCH_HEADER": "Authorization: Bearer t"}, clear=False)

    def test_http_remote_with_auth_dies(self):
        with self._auth_env(), pytest.raises(SystemExit) as e:
            entrypoint._fetch("http://api.example.com/s")
        assert e.value.code == 2

    def test_http_localhost_with_auth_allowed(self):
        with self._auth_env():
            req = self._fetch_capture("http://localhost:8888/s")
        assert req.get_header("Authorization") == "Bearer t"

    def test_https_remote_with_auth_allowed(self):
        with self._auth_env():
            req = self._fetch_capture("https://api.example.com/s")
        assert req.get_header("Authorization") == "Bearer t"

    def test_http_remote_without_auth_ok(self):
        env = {k: v for k, v in __import__("os").environ.items() if k != "SAFE_FETCH_SEARCH_HEADER"}
        with mock.patch.dict("os.environ", env, clear=True):
            req = self._fetch_capture("http://api.example.com/s")
        assert req.get_header("Authorization") is None


class TestRedirectStripsCredential:
    """The search credential must not be resent to a different origin on 30x."""

    def _redirect(self, orig, newurl):
        h = entrypoint._ValidatingRedirectHandler()
        req = urllib.request.Request(orig, headers={"X-Subscription-Token": "secret"})  # noqa: S310
        return h.redirect_request(req, mock.MagicMock(), 302, "Found", mock.MagicMock(), newurl)

    def _auth_env(self):
        return mock.patch.dict("os.environ", {"SAFE_FETCH_SEARCH_HEADER": "X-Subscription-Token: secret"}, clear=False)

    def test_cross_origin_strips_auth(self):
        with self._auth_env():
            new = self._redirect("https://api.example.com/s", "https://evil.example.com/")
        assert new is not None
        assert new.get_header("X-subscription-token") is None

    def test_same_origin_keeps_auth(self):
        with self._auth_env():
            new = self._redirect("https://api.example.com/s", "https://api.example.com/s2")
        assert new.get_header("X-subscription-token") == "secret"

    def test_scheme_downgrade_strips_auth(self):
        with self._auth_env():
            new = self._redirect("https://api.example.com/s", "http://api.example.com/s")
        assert new.get_header("X-subscription-token") is None
