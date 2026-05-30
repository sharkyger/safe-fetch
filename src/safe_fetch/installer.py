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

import atexit
import json
import os
import shutil
import stat
from contextlib import ExitStack
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


# Module-level lifecycle for the bundled-data path.
#
# When the package is installed loose-on-disk (the common pip layout),
# ``as_file`` is a no-op and returns the on-disk path directly. When the
# package is loaded from a zip/wheel without extraction (rare but
# supported), ``as_file`` extracts the resource into a temporary
# directory and cleans it up on context-manager exit. The previous
# implementation returned ``Path(p)`` from inside a closed ``with``
# block — for zip-loaded packages this yielded a dangling path.
#
# The fix keeps the context manager alive for the process lifetime via
# a module-level ExitStack and caches the resolved Path so subsequent
# callers don't repeatedly enter a fresh context (which would leak
# temp directories on the zip path).
_resource_stack = ExitStack()
atexit.register(_resource_stack.close)
_data_root_cache: Path | None = None


def _data_root() -> Path:
    """Resolve the bundled ``data/`` dir to a real Path that stays valid
    for the rest of the process.
    """
    global _data_root_cache
    if _data_root_cache is None:
        root = files("safe_fetch") / "data"
        _data_root_cache = Path(_resource_stack.enter_context(as_file(root)))
    return _data_root_cache


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


_EXEC_MASK = stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH


def _install_hooks(target: Path, *, dry_run: bool) -> list[Action]:
    out_dir = target / "hooks"
    actions: list[Action] = []
    if not dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
    for name in HOOK_FILES:
        dst = out_dir / name
        src = _bundled("hooks", name)
        if dst.exists() and dst.read_bytes() == src.read_bytes():
            # Bytes match — but if any exec bit was stripped externally
            # (e.g. operator ran chmod go-x by mistake) reinstall must
            # heal it rather than reporting "skip — already installed".
            # Requiring ALL bits in _EXEC_MASK catches partial strips too.
            if (dst.stat().st_mode & _EXEC_MASK) == _EXEC_MASK:
                actions.append(Action("skip", dst, "already installed"))
                continue
            actions.append(Action("update", dst, "restored executable bits"))
            if not dry_run:
                dst.chmod(dst.stat().st_mode | _EXEC_MASK)
            continue
        actions.append(Action("create" if not dst.exists() else "update", dst))
        if not dry_run:
            shutil.copyfile(src, dst)
            dst.chmod(dst.stat().st_mode | _EXEC_MASK)
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
            entry.get("matcher") == matcher and any(h.get("command") == cmd for h in entry.get("hooks", []))
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

    # Anchor on hooks_prefix + os.sep so a sibling directory whose name
    # merely shares the prefix (`<target>/hooks-backup/...`,
    # `<target>/hooksy/...`) doesn't get accidentally swept along with
    # the managed `<target>/hooks/...` entries.
    hooks_prefix = str((target / "hooks").resolve())
    hooks_prefix_with_sep = hooks_prefix + os.sep
    changed = False
    for category in list(data["hooks"].keys()):
        new_entries: list[dict] = []
        for entry in data["hooks"][category]:
            kept_hooks = [
                h for h in entry.get("hooks", []) if not h.get("command", "").startswith(hooks_prefix_with_sep)
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
    # Search for END strictly AFTER the located BEGIN. If a stray END
    # marker appears earlier in the file (e.g. quoted in operator prose
    # before the managed block), an unanchored first-match would pick
    # that one — yielding a slice that leaves the real snippet in
    # place. If no END follows BEGIN, the block is malformed; skip.
    end_idx = content.find(SNIPPET_END_MARK, begin)
    if end_idx == -1:
        return [Action("skip", claude_md, "no END marker after BEGIN")]
    end = end_idx + len(SNIPPET_END_MARK)
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
