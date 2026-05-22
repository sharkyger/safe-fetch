"""Live end-to-end smoke test for safe-fetch.

The unit tests in ``test_safe_fetch_cli.py`` mock subprocess and never
launch the Docker container; the unit tests in
``test_self_test_attack_page.py`` exercise the sanitizer but bypass
Docker entirely. This file closes the gap: it actually runs the
``safe-fetch:latest`` image against a known-benign page served from
the host, and verifies the contract the rest of the system relies on:

  1. ``<UNTRUSTED-WEB url="...">...</UNTRUSTED-WEB>`` envelope is
     present on the output.
  2. The URL in the opening tag matches what we asked for.
  3. The envelope body is non-empty (sanitizer didn't strip everything
     and leave a hollow wrap).
  4. The output is within the 20 KB sanitizer cap.

The point of testing this on a *benign* page is exactly the inverse of
the adversarial fixtures: if the envelope is absent on a clean fetch,
the sanitizer is silently failing open — which would mean attacks
slip through too. Clean-input contract verification is the canary.

Skipped automatically when Docker is not available or the
``safe-fetch:latest`` image hasn't been built. Run
``docker/build.sh`` first to make this test go green.
"""

from __future__ import annotations

import http.server
import os
import socket
import socketserver
import subprocess
import threading
import time
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).parent.parent
FIXTURES_DIR = REPO_ROOT / "tests" / "fixtures"
SRC_DIR = REPO_ROOT / "src"
IMAGE_NAME = "safe-fetch:latest"


# ── pre-flight ───────────────────────────────────────────────────────


def _docker_available() -> bool:
    try:
        r = subprocess.run(["docker", "info"], capture_output=True, timeout=5, check=False)
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _image_built() -> bool:
    try:
        r = subprocess.run(
            ["docker", "image", "inspect", IMAGE_NAME],
            capture_output=True,
            timeout=5,
            check=False,
        )
        return r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


pytestmark = [
    pytest.mark.skipif(not _docker_available(), reason="docker not available"),
    pytest.mark.skipif(
        _docker_available() and not _image_built(),
        reason=f"{IMAGE_NAME} not built — run docker/build.sh",
    ),
]


# ── local http server for the benign fixture ────────────────────────


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


class _SilentHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, *_args, **_kwargs):  # silence stderr noise during pytest
        pass


@pytest.fixture(scope="module")
def benign_server():
    """Spin up an http.server on a free port serving the fixtures dir;
    tear it down when the module finishes.

    Not safe under pytest-xdist (module-scope chdir would mutate the
    worker's cwd globally). The repo doesn't currently use xdist; if
    it ever does, move this fixture to per-test scope and use an
    explicit Path() base instead of chdir.
    """
    port = _free_port()

    # SimpleHTTPRequestHandler resolves paths against cwd by default;
    # chdir into the fixtures dir for the duration of the module.
    class _Server(socketserver.TCPServer):
        allow_reuse_address = True

    cwd_before = Path.cwd()
    os.chdir(FIXTURES_DIR)
    httpd = _Server(("127.0.0.1", port), _SilentHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    # Wait briefly for the listener to be ready
    for _ in range(20):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                break
        except OSError:
            time.sleep(0.05)
    try:
        yield port
    finally:
        httpd.shutdown()
        httpd.server_close()
        os.chdir(cwd_before)


def _run_safe_fetch(url: str) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(SRC_DIR)
    return subprocess.run(
        ["python3", "-m", "safe_fetch", url],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
        env=env,
    )


@pytest.fixture
def benign_url(benign_server):
    """URL the in-container fetch should use to reach the host's
    fixture server. ``host.docker.internal`` resolves on Docker Desktop
    (Mac/Win). On Linux, --add-host=host.docker.internal:host-gateway
    or --network=host would be needed; if we land on Linux later, add
    a conditional override here.
    """
    return f"http://host.docker.internal:{benign_server}/clean-page.html"


# ── the smoke test itself ────────────────────────────────────────────


class TestBenignFetchEnvelope:
    """The minimum contract on a clean page.

    If any of these fail, the sanitizer has lost its data-flagging
    guarantee — and that means attacks slip through too, not just
    benign content.
    """

    def test_runs_and_exits_zero(self, benign_url):
        r = _run_safe_fetch(benign_url)
        assert r.returncode == 0, f"safe-fetch failed: {r.stderr}"

    def test_output_is_wrapped_in_untrusted_envelope(self, benign_url):
        r = _run_safe_fetch(benign_url)
        assert f'<UNTRUSTED-WEB url="{benign_url}">' in r.stdout, (
            "envelope opening tag missing or URL mismatch — clean-page fetch is not being flagged as untrusted"
        )
        assert "</UNTRUSTED-WEB>" in r.stdout, "envelope closing tag missing"

    def test_envelope_body_is_not_empty(self, benign_url):
        r = _run_safe_fetch(benign_url)
        opener = r.stdout.find('">', r.stdout.find("<UNTRUSTED-WEB")) + 2
        closer = r.stdout.find("</UNTRUSTED-WEB>")
        assert opener > 1 and closer > opener
        body = r.stdout[opener:closer].strip()
        assert body, "envelope body is empty — sanitizer ate the whole page"

    def test_output_within_sanitizer_length_cap(self, benign_url):
        r = _run_safe_fetch(benign_url)
        # Hard cap from sanitizer; clean-page is tiny so this is just a
        # contract check, not a real boundary stress.
        assert len(r.stdout.encode("utf-8")) <= 20_480
