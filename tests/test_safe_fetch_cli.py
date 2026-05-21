"""Tests for safe-fetch CLI (host-side Docker wrapper).

The CLI is the host-side entry point that invokes the locked-down
``safe-fetch:latest`` Docker image. We never run Docker in tests — the
contract under test is purely:

  1. Argv validation (one URL, http/https only, no control chars).
  2. Docker pre-flight: if ``docker info`` fails, exit 2 with a loud
     install hint instead of trying to run the container.
  3. The exact subprocess argv built for ``docker run`` — every
     hardening flag in scope doc Part 2 must be present.

The actual container behavior is verified manually via the smoke test
in the plan file. See ``docs/roadmaps/injection-gate-pillar.md``
Part 5 MVP item 1 and Part 8 Session-B steps 2-3.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest import mock

REPO_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from safe_fetch import cli  # noqa: E402

# ── helpers ──────────────────────────────────────────────────────────


def _docker_ok():
    return mock.patch.object(cli, "_check_docker", return_value=True)


def _docker_missing():
    return mock.patch.object(cli, "_check_docker", return_value=False)


# ── _validate_url ────────────────────────────────────────────────────


class TestValidateUrl:
    def test_https_url_passes(self):
        assert cli._validate_url("https://docs.anthropic.com/en/foo") is None

    def test_http_url_passes(self):
        assert cli._validate_url("http://example.com/") is None

    def test_empty_rejected(self):
        assert cli._validate_url("") is not None

    def test_file_scheme_rejected(self):
        err = cli._validate_url("file:///etc/passwd")
        assert err is not None and "scheme" in err

    def test_javascript_scheme_rejected(self):
        err = cli._validate_url("javascript:alert(1)")
        assert err is not None and "scheme" in err

    def test_no_host_rejected(self):
        err = cli._validate_url("https:///path")
        assert err is not None and "host" in err

    def test_control_char_rejected(self):
        err = cli._validate_url("https://example.com/\nLocation: evil")
        assert err is not None and "control" in err


# ── _build_docker_command ────────────────────────────────────────────


class TestBuildDockerCommand:
    """The hardened-flag contract from scope Part 2 / Part 5 MVP item 1.

    These assertions are deliberately exact — a missing or relaxed flag
    is a security regression and must fail the test.
    """

    def setup_method(self):
        self.cmd = cli._build_docker_command("https://example.com/")

    def test_starts_with_docker_run(self):
        assert self.cmd[:2] == ["docker", "run"]

    def test_ephemeral(self):
        assert "--rm" in self.cmd

    def test_network_bridge(self):
        assert "--network=bridge" in self.cmd

    def test_read_only_rootfs(self):
        assert "--read-only" in self.cmd

    def test_tmpfs_locked_down(self):
        assert "--tmpfs" in self.cmd
        i = self.cmd.index("--tmpfs")
        spec = self.cmd[i + 1]
        assert spec.startswith("/tmp:")  # noqa: S108 — tmpfs spec, not host path
        assert "noexec" in spec
        assert "nosuid" in spec
        assert "size=" in spec

    def test_cap_drop_all(self):
        assert "--cap-drop=ALL" in self.cmd

    def test_no_new_privileges(self):
        assert "--security-opt" in self.cmd
        i = self.cmd.index("--security-opt")
        assert self.cmd[i + 1] == "no-new-privileges"

    def test_non_root_user(self):
        assert "--user" in self.cmd
        i = self.cmd.index("--user")
        assert self.cmd[i + 1] == "nobody"

    def test_memory_ceiling(self):
        assert "--memory=256m" in self.cmd
        # Memory == swap, otherwise swap is a memory-ceiling escape hatch
        assert "--memory-swap=256m" in self.cmd

    def test_pids_limit(self):
        assert "--pids-limit=50" in self.cmd

    def test_cpu_ceiling(self):
        assert "--cpus=0.5" in self.cmd

    def test_nofile_ulimit(self):
        assert "--ulimit" in self.cmd
        i = self.cmd.index("--ulimit")
        assert self.cmd[i + 1] == "nofile=128:128"

    def test_image_then_url_at_end(self):
        assert self.cmd[-2] == cli.IMAGE_NAME
        assert self.cmd[-1] == "https://example.com/"

    def test_url_is_positional_not_flag(self):
        # If someone refactors and accidentally puts the URL before the
        # image, an attacker who controls the URL could pass it as a
        # docker flag. Verify position is strictly last.
        assert self.cmd.count("https://example.com/") == 1
        assert self.cmd.index("https://example.com/") == len(self.cmd) - 1


# ── main() ───────────────────────────────────────────────────────────


class TestMainExitCodes:
    def test_no_args_prints_usage_and_exits_2(self, capsys):
        rc = cli.main([])
        out = capsys.readouterr()
        assert rc == 2
        assert "Usage" in out.err

    def test_too_many_args_prints_usage_and_exits_2(self, capsys):
        rc = cli.main(["https://a.example/", "https://b.example/"])
        assert rc == 2
        assert "Usage" in capsys.readouterr().err

    def test_bad_scheme_exits_2(self, capsys):
        rc = cli.main(["file:///etc/passwd"])
        assert rc == 2
        assert "scheme" in capsys.readouterr().err

    def test_docker_missing_exits_2_with_install_hint(self, capsys):
        with _docker_missing():
            rc = cli.main(["https://example.com/"])
        err = capsys.readouterr().err
        assert rc == 2
        assert "Docker" in err
        assert "install" in err.lower() or "get-docker" in err.lower()

    def test_docker_present_invokes_subprocess(self, capsys):
        with _docker_ok(), mock.patch.object(cli.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
            rc = cli.main(["https://docs.anthropic.com/x"])
        assert rc == 0
        run.assert_called_once()
        called_cmd = run.call_args.args[0]
        # Must be the hardened command from _build_docker_command, not
        # some ad-hoc variant.
        expected = cli._build_docker_command("https://docs.anthropic.com/x")
        assert called_cmd == expected

    def test_docker_failure_propagates_returncode(self):
        with _docker_ok(), mock.patch.object(cli.subprocess, "run") as run:
            run.return_value = subprocess.CompletedProcess(args=[], returncode=7)
            rc = cli.main(["https://example.com/"])
        assert rc == 7


# ── _check_docker ────────────────────────────────────────────────────


class TestCheckDocker:
    def test_returns_false_when_docker_binary_missing(self):
        with mock.patch.object(cli.shutil, "which", return_value=None):
            assert cli._check_docker() is False

    def test_returns_false_when_docker_info_fails(self):
        with (
            mock.patch.object(cli.shutil, "which", return_value="/usr/bin/docker"),
            mock.patch.object(cli.subprocess, "run") as run,
        ):
            run.return_value = subprocess.CompletedProcess(args=[], returncode=1)
            assert cli._check_docker() is False

    def test_returns_true_when_docker_info_ok(self):
        with (
            mock.patch.object(cli.shutil, "which", return_value="/usr/bin/docker"),
            mock.patch.object(cli.subprocess, "run") as run,
        ):
            run.return_value = subprocess.CompletedProcess(args=[], returncode=0)
            assert cli._check_docker() is True

    def test_docker_info_timeout_returns_false(self):
        with (
            mock.patch.object(cli.shutil, "which", return_value="/usr/bin/docker"),
            mock.patch.object(cli.subprocess, "run", side_effect=subprocess.TimeoutExpired(cmd="docker", timeout=5)),
        ):
            assert cli._check_docker() is False
