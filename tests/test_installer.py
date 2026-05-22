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


# ── helpers ─────────────────────────────────────────────────────────


def _snapshot(root: Path) -> dict[str, bytes]:
    """Return a {relative-path: content-bytes} snapshot for diff checks."""
    return {
        str(p.relative_to(root)): p.read_bytes()
        for p in sorted(root.rglob("*"))
        if p.is_file()
    }
