#!/bin/bash
# PreToolUse hook on Write/Edit — single-use marker-file gate for the
# five protected destination categories.
#
# Categorization (case statement below):
#   - rule     → CLAUDE.md
#   - settings → .claude/settings.json + settings.local.json
#   - hook     → .claude/hooks/*.sh
#   - skill    → skills/*/SKILL.md, .claude/skills/*
#   - memory   → */memory/*.md, */agent-memory/*.md
#   - other    → pass (exit 0); unprotected
#
# Marker semantics mirror .claude/hooks/mark-code-review.sh:
#   - Marker dir:  /tmp/.claude-injection-gate/
#   - Marker name: {category}-{sha256_first_16(abs_path)}
#   - Touched by the corresponding /save-* or /edit-* slash command;
#     consumed (rm) by this hook on a matching Write/Edit.
#   - sha256(abs_path) binds the marker to the EXACT path AND category
#     so a marker for path A cannot unlock a write to path B.
#
# Why marker-file pattern (and not, say, an in-process flag):
#   - The agent cannot forge the marker — only the slash command body
#     (executed by the harness, not by the agent's tool call) writes it.
#   - It matches the prior art the user already trusts
#     (mark-code-review.sh / require-code-review.sh).
#
# Known limitations (v1):
#   - Path normalization: the marker key is derived from the LITERAL
#     PATH_RAW string the harness passes in tool_input.file_path. Two
#     paths that resolve to the same file but differ textually
#     (`/a/./b` vs `/a/b`, `/a/../a/b` vs `/a/b`, symlink alias vs
#     target) hash differently and need separate markers. In practice
#     the harness passes absolute canonical paths, but a hand-crafted
#     Write with a non-canonical file_path would miss a marker for the
#     canonical form. This fails CLOSED — a non-matching write is
#     correctly blocked rather than mis-authorized — so it is a UX
#     paper-cut, not a security gap.
#   - TOCTOU between [ -f "$MARKER" ] and rm -f "$MARKER" is a race in
#     principle, but the harness currently serializes tool calls (one
#     PreToolUse hook fires at a time, as of Claude Code's single-
#     tool-call execution model) and the marker is bound to one
#     specific (category, path) pair — no shared resource a parallel
#     call could exploit. No mitigation needed today; revisit if a
#     multi-agent / parallel-tool model lands.
#
# See https://github.com/sharkyger/claude-code-prompt-injection-gate
# for the marker-file rationale.

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // empty')

case "$TOOL" in
  Write|Edit) ;;
  *) exit 0 ;;
esac

PATH_RAW=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')
if [ -z "$PATH_RAW" ]; then
  exit 0
fi

# Categorize. The patterns are deliberately path-suffix oriented so
# they catch the protected files regardless of where the repo lives.
CATEGORY=""
SLASH_CMD=""
case "$PATH_RAW" in
  */CLAUDE.md|CLAUDE.md)
    CATEGORY="rule"
    SLASH_CMD="/save-rule"
    ;;
  */.claude/settings.json|*/.claude/settings.local.json)
    CATEGORY="settings"
    SLASH_CMD="/edit-settings"
    ;;
  */.claude/hooks/*.sh)
    CATEGORY="hook"
    SLASH_CMD="/edit-hook"
    ;;
  */skills/*/SKILL.md|*/.claude/skills/*)
    CATEGORY="skill"
    SLASH_CMD="/edit-skill"
    ;;
  */memory/*.md|*/agent-memory/*.md)
    CATEGORY="memory"
    SLASH_CMD="/save-memory"
    ;;
  *)
    # Unprotected path — pass through.
    exit 0
    ;;
esac

# Compute the marker key. Must match the slash command's hash exactly.
HASH=$(printf '%s' "$PATH_RAW" | shasum -a 256 | cut -c1-16)
MARKER="/tmp/.claude-injection-gate/${CATEGORY}-${HASH}"

if [ ! -f "$MARKER" ]; then
  cat >&2 <<MSG
BLOCKED: ${CATEGORY} edit requires explicit operator approval.

  Path: ${PATH_RAW}

Ask the operator to run:

  ${SLASH_CMD} ${PATH_RAW}

This writes a single-use marker that authorizes the next Write/Edit
to exactly this path. The marker is consumed on first matching write
so each authorized edit is one-shot.

Why this exists: prompt-injected content could otherwise steer the
agent into poisoning CLAUDE.md / a hook / a skill / settings.json /
project memory. See https://github.com/sharkyger/claude-code-prompt-injection-gate for the full threat model.
MSG
  exit 2
fi

# Marker present — consume it and allow the write.
rm -f "$MARKER"
exit 0
