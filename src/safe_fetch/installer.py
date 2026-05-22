"""Idempotent installer for the claude-code-prompt-injection-gate bundle.

``safe-fetch --install-claude-hooks`` writes four PreToolUse/PostToolUse
hooks, five operator slash commands, and a CLAUDE.md Layer-4 snippet
into the target dir (default ``~/.claude/``). It merges into existing
``settings.json`` without clobbering unrelated keys, and is fully
reversible via ``--uninstall-claude-hooks``.

Design notes:

- Source-of-truth files live in ``safe_fetch/data/`` and are bundled
  as setuptools package-data (see ``pyproject.toml``).
- Snippet idempotency is enforced by sentinel HTML comments
  (``SNIPPET_BEGIN_MARK`` / ``SNIPPET_END_MARK``). If both markers
  are present, the block is treated as operator-managed and left
  untouched on re-install. Uninstall removes the block bounded by
  the markers.
- ``settings.json`` merge: hook entries are keyed by their absolute
  command path. The installer's entries are added if missing, never
  duplicated. Uninstall removes entries whose command points into the
  target's ``hooks/`` dir; user-added entries on the same matcher
  survive.
- ``dry_run`` returns the action plan without writing anything.
"""

from __future__ import annotations

import json
import shutil
import stat
from dataclasses import dataclass
from importlib.resources import as_file, files
from pathlib import Path

# ── source-of-truth manifest ────────────────────────────────────────

HOOK_FILES: tuple[str, ...] = (
    "injection-gate-agent.sh",
    "injection-gate-bash.sh",
    "injection-gate-webfetch.sh",
    "injection-gate-write-edit.sh",
)

COMMAND_FILES: tuple[str, ...] = (
    "save-memory.md",
    "save-rule.md",
    "edit-skill.md",
    "edit-settings.md",
    "edit-hook.md",
)

# (category, matcher, source-hook-filename)
HOOK_REGISTRY: tuple[tuple[str, str, str], ...] = (
    ("PreToolUse", "WebFetch", "injection-gate-webfetch.sh"),
    ("PreToolUse", "Bash", "injection-gate-bash.sh"),
    ("PreToolUse", "Write|Edit", "injection-gate-write-edit.sh"),
    ("PostToolUse", "Agent", "injection-gate-agent.sh"),
)

SNIPPET_BEGIN_MARK = "<!-- safe-fetch:hook-snippet:begin -->"
SNIPPET_END_MARK = "<!-- safe-fetch:hook-snippet:end -->"


@dataclass
class Action:
    """One filesystem change the installer performed (or would perform)."""

    kind: str  # 'create', 'update', 'skip', 'remove'
    path: Path
    detail: str = ""


# ── package-data accessors ──────────────────────────────────────────


def _data_root() -> Path:
    """Resolve the bundled data/ dir to a real Path.

    Using ``as_file`` ensures correctness when the package is installed
    from a zip/wheel — the ``files()`` Traversable may not be a real
    filesystem path. For a normal pip install this resolves to the
    package's data/ subdir directly.
    """
    root = files("safe_fetch") / "data"
    with as_file(root) as p:
        return Path(p)


def _bundled(*parts: str) -> Path:
    return _data_root().joinpath(*parts)


# ── installers ──────────────────────────────────────────────────────


def install(target: Path, *, dry_run: bool = False) -> list[Action]:
    """Install the hook bundle into ``target`` (typically ``~/.claude/``).

    Idempotent: re-running yields all-skip actions and no diff.
    Returns the list of actions taken (or planned, if dry_run).
    """
    target = Path(target).expanduser()
    actions: list[Action] = []

    if not dry_run:
        target.mkdir(parents=True, exist_ok=True)

    actions.extend(_install_hooks(target, dry_run=dry_run))
    actions.extend(_install_commands(target, dry_run=dry_run))
    actions.extend(_merge_settings(target, dry_run=dry_run))
    actions.extend(_inject_snippet(target, dry_run=dry_run))
    return actions


def uninstall(target: Path, *, dry_run: bool = False) -> list[Action]:
    """Reverse ``install``. Leaves untouched user config intact."""
    target = Path(target).expanduser()
    actions: list[Action] = []
    actions.extend(_remove_hooks(target, dry_run=dry_run))
    actions.extend(_remove_commands(target, dry_run=dry_run))
    actions.extend(_unmerge_settings(target, dry_run=dry_run))
    actions.extend(_strip_snippet(target, dry_run=dry_run))
    return actions


# ── hook + command copy ─────────────────────────────────────────────


def _install_hooks(target: Path, *, dry_run: bool) -> list[Action]:
    out_dir = target / "hooks"
    actions: list[Action] = []
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
    for name in HOOK_FILES:
        dst = out_dir / name
        src = _bundled("hooks", name)
        if dst.exists() and dst.read_bytes() == src.read_bytes():
            actions.append(Action("skip", dst, "already installed"))
            continue
        actions.append(Action("create" if not dst.exists() else "update", dst))
        if not dry_run:
            shutil.copyfile(src, dst)
            dst.chmod(dst.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return actions


def _install_commands(target: Path, *, dry_run: bool) -> list[Action]:
    out_dir = target / "commands"
    actions: list[Action] = []
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
    for name in COMMAND_FILES:
        dst = out_dir / name
        src = _bundled("commands", name)
        if dst.exists() and dst.read_bytes() == src.read_bytes():
            actions.append(Action("skip", dst, "already installed"))
            continue
        actions.append(Action("create" if not dst.exists() else "update", dst))
        if not dry_run:
            shutil.copyfile(src, dst)
    return actions


# ── settings.json merge ─────────────────────────────────────────────


def _hook_command_path(target: Path, hook_filename: str) -> str:
    return str((target / "hooks" / hook_filename).resolve())


def _our_hook_entry(matcher: str, command_path: str) -> dict:
    return {
        "matcher": matcher,
        "hooks": [{"type": "command", "command": command_path}],
    }


def _merge_settings(target: Path, *, dry_run: bool) -> list[Action]:
    settings_path = target / "settings.json"
    data = _load_settings(settings_path)
    changed = False

    data.setdefault("hooks", {})

    for category, matcher, hook_filename in HOOK_REGISTRY:
        data["hooks"].setdefault(category, [])
        cmd = _hook_command_path(target, hook_filename)
        already_present = any(
            entry.get("matcher") == matcher
            and any(h.get("command") == cmd for h in entry.get("hooks", []))
            for entry in data["hooks"][category]
        )
        if already_present:
            continue
        data["hooks"][category].append(_our_hook_entry(matcher, cmd))
        changed = True

    if not changed:
        return [Action("skip", settings_path, "hook entries already present")]

    if not dry_run:
        settings_path.write_text(json.dumps(data, indent=2) + "\n")
    return [Action("update" if settings_path.exists() else "create", settings_path)]


def _unmerge_settings(target: Path, *, dry_run: bool) -> list[Action]:
    settings_path = target / "settings.json"
    if not settings_path.exists():
        return []
    data = _load_settings(settings_path)
    if "hooks" not in data:
        return []

    hooks_prefix = str((target / "hooks").resolve())
    changed = False
    for category in list(data["hooks"].keys()):
        new_entries: list[dict] = []
        for entry in data["hooks"][category]:
            kept_hooks = [
                h for h in entry.get("hooks", [])
                if not h.get("command", "").startswith(hooks_prefix)
            ]
            if not kept_hooks:
                changed = True
                continue
            if len(kept_hooks) != len(entry.get("hooks", [])):
                entry = {**entry, "hooks": kept_hooks}
                changed = True
            new_entries.append(entry)
        if new_entries != data["hooks"][category]:
            data["hooks"][category] = new_entries
            changed = True

    if not changed:
        return [Action("skip", settings_path, "nothing to remove")]
    if not dry_run:
        settings_path.write_text(json.dumps(data, indent=2) + "\n")
    return [Action("update", settings_path, "stripped our hook entries")]


def _load_settings(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text() or "{}")
    except json.JSONDecodeError:
        # Corrupt settings.json — refuse to merge into garbage.
        raise InstallerError(f"existing settings.json is not valid JSON: {path}") from None


# ── CLAUDE.md snippet injection ─────────────────────────────────────


def _snippet_body() -> str:
    return _bundled("snippets", "claude_md.md").read_text(encoding="utf-8")


def _bracketed_snippet() -> str:
    return f"{SNIPPET_BEGIN_MARK}\n{_snippet_body()}\n{SNIPPET_END_MARK}\n"


def _inject_snippet(target: Path, *, dry_run: bool) -> list[Action]:
    claude_md = target / "CLAUDE.md"
    if claude_md.exists():
        content = claude_md.read_text(encoding="utf-8")
        if SNIPPET_BEGIN_MARK in content and SNIPPET_END_MARK in content:
            return [Action("skip", claude_md, "snippet markers already present")]
        new_content = content.rstrip() + "\n\n" + _bracketed_snippet()
        if not dry_run:
            claude_md.write_text(new_content, encoding="utf-8")
        return [Action("update", claude_md, "appended snippet block")]
    if not dry_run:
        claude_md.write_text(_bracketed_snippet(), encoding="utf-8")
    return [Action("create", claude_md)]


def _strip_snippet(target: Path, *, dry_run: bool) -> list[Action]:
    claude_md = target / "CLAUDE.md"
    if not claude_md.exists():
        return []
    content = claude_md.read_text(encoding="utf-8")
    if SNIPPET_BEGIN_MARK not in content or SNIPPET_END_MARK not in content:
        return [Action("skip", claude_md, "no snippet to remove")]
    begin = content.index(SNIPPET_BEGIN_MARK)
    end = content.index(SNIPPET_END_MARK) + len(SNIPPET_END_MARK)
    # Strip the block + the surrounding blank line we appended at install.
    stripped = (content[:begin].rstrip() + "\n" + content[end:].lstrip("\n")).rstrip() + "\n"
    if stripped.strip() == "":
        # Whole file was just our snippet — delete the file outright.
        if not dry_run:
            claude_md.unlink()
        return [Action("remove", claude_md, "file contained only our snippet")]
    if not dry_run:
        claude_md.write_text(stripped, encoding="utf-8")
    return [Action("update", claude_md, "stripped snippet block")]


# ── removal helpers ─────────────────────────────────────────────────


def _remove_hooks(target: Path, *, dry_run: bool) -> list[Action]:
    actions: list[Action] = []
    out_dir = target / "hooks"
    for name in HOOK_FILES:
        f = out_dir / name
        if f.exists():
            actions.append(Action("remove", f))
            if not dry_run:
                f.unlink()
    return actions


def _remove_commands(target: Path, *, dry_run: bool) -> list[Action]:
    actions: list[Action] = []
    out_dir = target / "commands"
    for name in COMMAND_FILES:
        f = out_dir / name
        if f.exists():
            actions.append(Action("remove", f))
            if not dry_run:
                f.unlink()
    return actions


# ── exceptions ──────────────────────────────────────────────────────


class InstallerError(RuntimeError):
    """Raised for unrecoverable installer states (e.g. corrupt settings)."""


__all__ = (
    "Action",
    "COMMAND_FILES",
    "HOOK_FILES",
    "HOOK_REGISTRY",
    "InstallerError",
    "SNIPPET_BEGIN_MARK",
    "SNIPPET_END_MARK",
    "install",
    "uninstall",
)
