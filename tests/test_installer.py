"""Tests for the ``safe-fetch --install-claude-hooks`` installer.

The installer writes Claude Code hooks + operator slash commands +
CLAUDE.md Layer-4 snippet into a target dir (default ``~/.claude/``).
It must be idempotent (re-run = no diff), merge into existing
settings.json without clobbering unrelated config, and fully reversible
via ``--uninstall-claude-hooks``.

Test architecture: every test uses a ``tmp_target`` fixture (an empty
tmp_path acting as a fake ``~/.claude/``). No real filesystem is
touched outside that tmp_path.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

import pytest

from safe_fetch import installer

# ── fixtures ────────────────────────────────────────────────────────


@pytest.fixture
def tmp_target(tmp_path: Path) -> Path:
    """A clean fake ~/.claude/ dir."""
    target = tmp_path / "claude"
    return target


# ── install: fresh state ────────────────────────────────────────────


class TestFreshInstall:
    def test_creates_target_dir_if_missing(self, tmp_target: Path):
        assert not tmp_target.exists()
        installer.install(tmp_target)
        assert tmp_target.is_dir()

    def test_writes_all_four_hook_files(self, tmp_target: Path):
        installer.install(tmp_target)
        hooks_dir = tmp_target / "hooks"
        for hook in installer.HOOK_FILES:
            f = hooks_dir / hook
            assert f.is_file(), f"hook missing: {hook}"
            assert f.read_text().startswith("#!/bin/bash"), f"hook header missing: {hook}"

    def test_hook_files_are_executable(self, tmp_target: Path):
        installer.install(tmp_target)
        for hook in installer.HOOK_FILES:
            f = tmp_target / "hooks" / hook
            mode = f.stat().st_mode
            assert mode & stat.S_IXUSR, f"hook not user-executable: {hook}"

    def test_writes_all_five_slash_commands(self, tmp_target: Path):
        installer.install(tmp_target)
        commands_dir = tmp_target / "commands"
        for cmd in installer.COMMAND_FILES:
            assert (commands_dir / cmd).is_file(), f"command missing: {cmd}"

    def test_creates_claude_md_with_snippet(self, tmp_target: Path):
        installer.install(tmp_target)
        claude_md = tmp_target / "CLAUDE.md"
        assert claude_md.is_file()
        content = claude_md.read_text()
        assert installer.SNIPPET_BEGIN_MARK in content
        assert installer.SNIPPET_END_MARK in content
        assert "Untrusted external content" in content

    def test_creates_settings_json_with_hook_entries(self, tmp_target: Path):
        installer.install(tmp_target)
        settings = tmp_target / "settings.json"
        assert settings.is_file()
        data = json.loads(settings.read_text())
        pre = data["hooks"]["PreToolUse"]
        post = data["hooks"]["PostToolUse"]
        matchers_pre = {entry["matcher"] for entry in pre}
        matchers_post = {entry["matcher"] for entry in post}
        assert matchers_pre == {"WebFetch", "Bash", "Write|Edit"}
        assert matchers_post == {"Agent"}

    def test_settings_hook_commands_point_into_target(self, tmp_target: Path):
        installer.install(tmp_target)
        data = json.loads((tmp_target / "settings.json").read_text())
        for category in ("PreToolUse", "PostToolUse"):
            for entry in data["hooks"][category]:
                for hook in entry["hooks"]:
                    cmd = hook["command"]
                    assert cmd.startswith(str(tmp_target / "hooks"))
                    assert cmd.endswith(".sh")


# ── install: idempotency ────────────────────────────────────────────


class TestIdempotency:
    def test_second_install_produces_no_diff(self, tmp_target: Path):
        installer.install(tmp_target)
        snapshot = _snapshot(tmp_target)
        installer.install(tmp_target)
        assert _snapshot(tmp_target) == snapshot

    def test_second_install_skips_existing_files(self, tmp_target: Path):
        installer.install(tmp_target)
        actions = installer.install(tmp_target)
        # On second run every action should be 'skip' (already present)
        kinds = [a.kind for a in actions]
        assert all(k == "skip" for k in kinds), f"non-skip actions on re-install: {actions}"

    def test_snippet_not_appended_twice(self, tmp_target: Path):
        installer.install(tmp_target)
        installer.install(tmp_target)
        installer.install(tmp_target)
        content = (tmp_target / "CLAUDE.md").read_text()
        assert content.count(installer.SNIPPET_BEGIN_MARK) == 1
        assert content.count(installer.SNIPPET_END_MARK) == 1

    def test_settings_hooks_not_duplicated(self, tmp_target: Path):
        installer.install(tmp_target)
        installer.install(tmp_target)
        data = json.loads((tmp_target / "settings.json").read_text())
        # Each matcher should appear exactly once
        seen = []
        for entry in data["hooks"]["PreToolUse"] + data["hooks"]["PostToolUse"]:
            seen.append(entry["matcher"])
        assert len(seen) == len(set(seen)), f"duplicate matchers: {seen}"


# ── install: respect existing config ────────────────────────────────


class TestPreservesExistingConfig:
    def test_preserves_unrelated_settings_keys(self, tmp_target: Path):
        tmp_target.mkdir(parents=True)
        existing = {"model": "claude-opus-4-7", "theme": "dark"}
        (tmp_target / "settings.json").write_text(json.dumps(existing))
        installer.install(tmp_target)
        data = json.loads((tmp_target / "settings.json").read_text())
        assert data["model"] == "claude-opus-4-7"
        assert data["theme"] == "dark"
        assert "hooks" in data

    def test_preserves_unrelated_hook_entries(self, tmp_target: Path):
        tmp_target.mkdir(parents=True)
        existing = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "WebFetch",
                        "hooks": [{"type": "command", "command": "/custom/user/hook.sh"}],
                    },
                    {
                        "matcher": "SomeOtherTool",
                        "hooks": [{"type": "command", "command": "/another/hook.sh"}],
                    },
                ],
            },
        }
        (tmp_target / "settings.json").write_text(json.dumps(existing))
        installer.install(tmp_target)
        data = json.loads((tmp_target / "settings.json").read_text())
        # User's custom WebFetch hook and SomeOtherTool entries survive
        commands = [
            h["command"]
            for entry in data["hooks"]["PreToolUse"]
            for h in entry["hooks"]
        ]
        assert "/custom/user/hook.sh" in commands
        assert "/another/hook.sh" in commands

    def test_appends_snippet_to_existing_claude_md(self, tmp_target: Path):
        tmp_target.mkdir(parents=True)
        original = "# My CLAUDE.md\n\nExisting content here.\n"
        (tmp_target / "CLAUDE.md").write_text(original)
        installer.install(tmp_target)
        content = (tmp_target / "CLAUDE.md").read_text()
        assert original.strip() in content
        assert installer.SNIPPET_BEGIN_MARK in content
        assert installer.SNIPPET_END_MARK in content
        # Snippet appended AFTER existing content, not prepended
        assert content.index(installer.SNIPPET_BEGIN_MARK) > content.index("Existing content")

    def test_skips_snippet_when_markers_already_present(self, tmp_target: Path):
        tmp_target.mkdir(parents=True)
        preexisting = (
            "# CLAUDE.md\n\n"
            f"{installer.SNIPPET_BEGIN_MARK}\n"
            "stale custom snippet content\n"
            f"{installer.SNIPPET_END_MARK}\n"
        )
        (tmp_target / "CLAUDE.md").write_text(preexisting)
        installer.install(tmp_target)
        # When markers exist, the installer treats the block as
        # operator-managed and does NOT touch it.
        content = (tmp_target / "CLAUDE.md").read_text()
        assert content.count(installer.SNIPPET_BEGIN_MARK) == 1
        assert "stale custom snippet content" in content


# ── dry-run ─────────────────────────────────────────────────────────


class TestDryRun:
    def test_dry_run_writes_nothing(self, tmp_target: Path):
        actions = installer.install(tmp_target, dry_run=True)
        assert not tmp_target.exists() or not any(tmp_target.iterdir())
        assert actions  # actions list should still describe what would happen

    def test_dry_run_action_kinds_are_create_when_fresh(self, tmp_target: Path):
        actions = installer.install(tmp_target, dry_run=True)
        # On a fresh target every action should be 'create'
        kinds = {a.kind for a in actions}
        assert "create" in kinds
        assert "remove" not in kinds


# ── uninstall ───────────────────────────────────────────────────────


class TestUninstall:
    def test_uninstall_removes_all_hook_files(self, tmp_target: Path):
        installer.install(tmp_target)
        installer.uninstall(tmp_target)
        for hook in installer.HOOK_FILES:
            assert not (tmp_target / "hooks" / hook).exists()

    def test_uninstall_removes_all_slash_commands(self, tmp_target: Path):
        installer.install(tmp_target)
        installer.uninstall(tmp_target)
        for cmd in installer.COMMAND_FILES:
            assert not (tmp_target / "commands" / cmd).exists()

    def test_uninstall_strips_snippet_block(self, tmp_target: Path):
        installer.install(tmp_target)
        installer.uninstall(tmp_target)
        if (tmp_target / "CLAUDE.md").exists():
            content = (tmp_target / "CLAUDE.md").read_text()
            assert installer.SNIPPET_BEGIN_MARK not in content
            assert installer.SNIPPET_END_MARK not in content

    def test_uninstall_removes_only_our_hook_entries(self, tmp_target: Path):
        tmp_target.mkdir(parents=True)
        existing = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "WebFetch",
                        "hooks": [{"type": "command", "command": "/custom/user/hook.sh"}],
                    },
                ],
            },
        }
        (tmp_target / "settings.json").write_text(json.dumps(existing))
        installer.install(tmp_target)
        installer.uninstall(tmp_target)
        data = json.loads((tmp_target / "settings.json").read_text())
        commands = [
            h["command"]
            for entry in data["hooks"].get("PreToolUse", [])
            for h in entry["hooks"]
        ]
        assert "/custom/user/hook.sh" in commands
        # Our hook command (path under tmp_target/hooks/) should be gone
        assert not any(c.startswith(str(tmp_target / "hooks")) for c in commands)

    def test_uninstall_preserves_unrelated_claude_md_content(self, tmp_target: Path):
        tmp_target.mkdir(parents=True)
        original = "# My CLAUDE.md\n\nExisting content.\n"
        (tmp_target / "CLAUDE.md").write_text(original)
        installer.install(tmp_target)
        installer.uninstall(tmp_target)
        content = (tmp_target / "CLAUDE.md").read_text()
        assert "Existing content" in content


# ── regression: deferred v0.1.1 findings ────────────────────────────


class TestDataRootStaysAccessible:
    """The _data_root helper must return a Path that remains valid for the
    duration of the process. The original implementation returned the path
    from inside an ``as_file()`` context manager whose ``__exit__`` ran
    before the function returned — for zip/wheel-loaded packages this
    yielded a Path to an already-cleaned-up temp dir. Even though
    pip-installed (loose) layouts didn't hit the bug, repeated calls
    should produce identical, readable paths.
    """

    def test_data_root_path_exists(self):
        p = installer._data_root()
        assert p.exists()
        assert p.is_dir()

    def test_bundled_files_are_readable(self):
        for hook in installer.HOOK_FILES:
            f = installer._bundled("hooks", hook)
            assert f.exists()
            content = f.read_bytes()
            assert content.startswith(b"#!/bin/bash")

    def test_data_root_is_stable_across_calls(self):
        p1 = installer._data_root()
        p2 = installer._data_root()
        assert p1 == p2

    def test_data_root_still_readable_after_repeated_access(self):
        # Simulates the lifecycle bug: even after multiple as_file
        # entries, the bundled file should remain accessible.
        for _ in range(10):
            installer._data_root()
        f = installer._bundled("hooks", "injection-gate-bash.sh")
        assert f.read_bytes().startswith(b"#!/bin/bash")

    def test_data_root_caches_as_file_entry(self, monkeypatch):
        # The lifecycle fix uses a module-level ExitStack to keep the
        # as_file context manager alive AND caches the resolved Path so
        # subsequent calls don't enter another context. This test
        # verifies the cache: as_file should be called once even after
        # many _data_root() calls.
        monkeypatch.setattr(installer, "_data_root_cache", None)
        real_as_file = installer.as_file
        call_count = {"n": 0}

        def counting_as_file(traversable):
            call_count["n"] += 1
            return real_as_file(traversable)

        monkeypatch.setattr(installer, "as_file", counting_as_file)
        for _ in range(5):
            installer._data_root()
        assert call_count["n"] == 1, (
            f"as_file called {call_count['n']} times — cache not honored, "
            "extracted temp dir from a zip-loaded package would be cleaned up "
            "before the path is read"
        )


class TestStripSnippetEndMarkerOrdering:
    """``_strip_snippet`` must locate the END marker AFTER the matched
    BEGIN. If a stray END appears before BEGIN (e.g. operator copied a
    marker comment into a code example earlier in the file), the original
    code took the first END occurrence — yielding a slice that left the
    real snippet body in place.
    """

    def test_stray_end_before_begin_does_not_break_strip(self, tmp_target: Path):
        tmp_target.mkdir(parents=True)
        # Put a stray END mark in earlier prose, then the real bracketed snippet.
        content = (
            f"# Earlier prose with stray marker\n"
            f"{installer.SNIPPET_END_MARK} (this is documentation, not paired)\n\n"
            f"More user content here.\n\n"
            f"{installer.SNIPPET_BEGIN_MARK}\n"
            f"Real snippet body — should be stripped.\n"
            f"{installer.SNIPPET_END_MARK}\n"
            f"\nTail content.\n"
        )
        (tmp_target / "CLAUDE.md").write_text(content)
        installer.uninstall(tmp_target)
        result = (tmp_target / "CLAUDE.md").read_text()
        assert installer.SNIPPET_BEGIN_MARK not in result
        assert "Real snippet body" not in result, (
            "snippet body survived strip — end-marker first-match bug"
        )
        # The stray END marker + surrounding prose stays.
        assert "Earlier prose with stray marker" in result
        assert "Tail content." in result


class TestUninstallPrefixIsPathBoundary:
    """``_unmerge_settings`` must only strip hook entries whose command
    is inside ``<target>/hooks/`` — not entries that merely share the
    string prefix (``<target>/hooks-backup/...``, ``<target>/hooksy/...``).
    """

    def test_unrelated_hooks_backup_entry_survives_uninstall(self, tmp_target: Path):
        tmp_target.mkdir(parents=True)
        backup_cmd = str(tmp_target / "hooks-backup" / "ours.sh")
        existing = {
            "hooks": {
                "PreToolUse": [
                    {
                        "matcher": "WebFetch",
                        "hooks": [{"type": "command", "command": backup_cmd}],
                    },
                ],
            },
        }
        (tmp_target / "settings.json").write_text(json.dumps(existing))
        installer.install(tmp_target)
        installer.uninstall(tmp_target)
        data = json.loads((tmp_target / "settings.json").read_text())
        commands = [
            h["command"]
            for entry in data["hooks"].get("PreToolUse", [])
            for h in entry["hooks"]
        ]
        assert backup_cmd in commands, (
            f"hooks-backup entry was incorrectly stripped: {commands}"
        )


class TestReinstallRestoresExecBits:
    """If a hook file's bytes match the bundled source but the exec bits
    were stripped externally (e.g. ``chmod -x``), reinstall should
    notice and re-set the executable bits rather than skipping.
    """

    def test_chmod_removes_exec_bits_then_reinstall_restores(self, tmp_target: Path):
        installer.install(tmp_target)
        hook = tmp_target / "hooks" / "injection-gate-bash.sh"
        # Strip exec bits
        hook.chmod(0o644)
        assert not (hook.stat().st_mode & stat.S_IXUSR)
        # Reinstall — should detect missing exec bits and restore
        installer.install(tmp_target)
        assert hook.stat().st_mode & stat.S_IXUSR, (
            "user-exec bit not restored on reinstall"
        )


# ── helpers ─────────────────────────────────────────────────────────


def _snapshot(root: Path) -> dict[str, bytes]:
    """Return a {relative-path: content-bytes} snapshot for diff checks."""
    return {
        str(p.relative_to(root)): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }
