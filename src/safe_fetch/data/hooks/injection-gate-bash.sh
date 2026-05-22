#!/bin/bash
# PreToolUse hook on Bash — two purposes, evaluated in order:
#   Stage 0: block any reference to the injection-gate marker dir,
#            so the agent can't forge a Write/Edit authorization marker
#            via the Bash tool. (Added in PR #54; closes the
#            marker-forge route the slash commands gate against.)
#   Stage 1+2: block raw curl/wget against non-allowlisted hosts;
#              tell the operator to use safe-fetch instead.
#
# Allowlist parity with .claude/hooks/injection-gate-webfetch.sh is
# deliberate. First-party Anthropic + own domains pass through; every
# other URL is routed through safe-fetch (Docker-isolated + sanitized).
# This is Session B's enforcement of scope Part 5 MVP item 4.
#
# Stage 1+2 approach: two-stage match (avoids the brittleness of a
# single all-purpose regex):
#   1. Verify the command actually INVOKES curl/wget at a command
#      boundary (start-of-string or after one of |&;`( — a plain space
#      doesn't count, so `man wget` and `git curl` don't match).
#   2. Scan the whole command for a host-shaped URL token. If none,
#      pass (e.g. `curl --version`, `wget --help`).
#
# Known limitations (mirrored from require-code-review.sh prior art):
# - Regex on raw command text, not a shell parser. A heredoc / python -c
#   body containing literal `curl example.com` triggers a false positive.
#   Mitigation: split tokens or use a placeholder in such strings.
# - `if cond; then curl x; fi` is not caught (curl follows `then`, not
#   a separator). Acceptable false negative for an obscure case.
# - Stage 0 is a literal substring match on the marker-dir path. Path
#   alias forms (brace expansion, string concatenation, encoded payloads,
#   symlink dereference, multi-call variable indirection) bypass it.
#   See the Stage-0 inline comment block for each class and the v2
#   mitigations being considered. Acceptable for v1; closes naive forge.
#
# See https://github.com/sharkyger/claude-code-prompt-injection-gate
# for the threat model and full architecture.

INPUT=$(cat)
TOOL=$(echo "$INPUT" | jq -r '.tool_name // empty')

if [ "$TOOL" != "Bash" ]; then
  exit 0
fi

COMMAND=$(echo "$INPUT" | jq -r '.tool_input.command // empty')
if [ -z "$COMMAND" ]; then
  exit 0
fi

# Stage 0: block any reference to the injection-gate marker dir.
#
# The Write/Edit hook gates writes to protected destinations behind a
# marker file at /tmp/.claude-injection-gate/{category}-{hash}. The
# Bash tool is otherwise free of that gate. Without this Stage 0, a
# steered agent could `touch /tmp/.claude-injection-gate/rule-{hash}`
# via Bash, then immediately Write CLAUDE.md, and the Write/Edit hook
# would consume the forged marker as if the operator had approved.
# The marker dir is the authorization protocol path — the agent has
# no legitimate reason to reference it. The operator can ls/touch it
# via the `!` prefix in chat (operator's shell, not the agent's
# Bash tool).
#
# Block scope: ANY reference to the literal substring. Read ops blocked
# too because a permissive read policy leaks info about which markers
# exist (useful for time-attacks against the gate).
#
# Known bypass limits (acceptable for v1, documented for v2):
#   - Brace expansion: `/tmp/.claude{,-}injection-gate` evades the
#     literal substring check. Closing it would require shell parsing.
#   - String concatenation: `"/tmp"/".claude-injection-gate"` — the
#     contiguous substring isn't present in the raw command; the shell
#     concatenates the adjacent quoted segments at parse time. Same
#     class: `/tmp/.claude-${EMPTY}injection-gate` and friends.
#   - Encoded payloads: `eval "touch $(printf L3RtcC8u…<base64>… | base64 -d)/rule"`
#     or `eval $'\x2f\x74\x6d\x70…'` — the path is reconstructed at
#     runtime; substring absent in the raw command. Same class covers
#     `python3 -c` / `perl -e` with an obfuscated string.
#   - Symlink dereference: agent creates /tmp/foo -> marker-dir, then
#     writes via /tmp/foo/...; the command text doesn't reference the
#     marker dir literally.
#   - Variable indirection across separate Bash calls: agent assigns
#     a var in one call, dereferences in another. We catch the
#     assignment if its value contains the substring; not the later
#     dereference if it doesn't.
#
# These bypasses all require an attacker sophisticated enough to chain
# multiple Bash invocations OR obfuscate the path — non-trivial cost
# for the attacker, while the simple substring block closes the
# "naive forge attempt" path that any unsophisticated injection would
# take. v2 mitigations: marker dir under a path the agent's user
# cannot symlink-target / write to (POSIX-ACL), OR HMAC-signed marker
# names with a key the agent doesn't have, OR shell parsing in the
# hook (heavy, brittle).
if echo "$COMMAND" | grep -qF '/tmp/.claude-injection-gate'; then
  cat >&2 <<MSG
BLOCKED: agent must not reference the injection-gate marker dir.

  Path:    /tmp/.claude-injection-gate
  Command: ${COMMAND}

This is the operator-authorization protocol path. The agent never
creates, lists, reads, or removes markers — that would defeat the
entire purpose of the gate. A marker proves operator approval, not
agent intent.

If a Write/Edit got blocked and you need a marker:
  - Ask the operator to run the appropriate slash command
    (/save-memory, /save-rule, /edit-skill, /edit-settings, /edit-hook)
  - Or ask the operator to touch the marker from their own shell
    via the ! prefix in chat (executes in operator context, not agent)

See https://github.com/sharkyger/claude-code-prompt-injection-gate for the threat model.
MSG
  exit 2
fi

# Stage 1: does the command invoke curl/wget at a command boundary?
# Word-boundary chars BEFORE: start-of-string OR shell separator
# (|, &, ;, backtick, open-paren). A plain space does NOT count —
# that's how we avoid catching `man wget` or `git curl-config`.
# Trailing boundary: space, end-of-string, or another shell separator —
# closes the `curl;rm` gap where a separator butts directly against
# the command name with no whitespace.
if ! echo "$COMMAND" \
     | grep -qE '(^|[|&;`(])[[:space:]]*(curl|wget)([[:space:]|&;]|$)'; then
  exit 0
fi

# Stage 2: find a host-shaped URL token anywhere in the command.
# The host token requires a TLD-like suffix (.[A-Za-z]{2,}) so flag
# values like `-o /tmp/file.bin` don't false-match.
URL_PART=$(
  echo "$COMMAND" \
  | grep -oE '(https?://)?[A-Za-z0-9][A-Za-z0-9.-]*\.[A-Za-z]{2,}([/?#][^[:space:]]*)?' \
  | head -1
)
if [ -z "$URL_PART" ]; then
  # curl/wget was invoked but no URL was supplied — `curl --version`,
  # `wget --help`. Not a fetch; pass through.
  exit 0
fi

# Extract host for allowlist comparison.
HOST=$(
  echo "$URL_PART" \
  | sed -E 's|^https?://||' \
  | sed -E 's|[/?#].*$||' \
  | tr '[:upper:]' '[:lower:]'
)

# Allowlist — must stay in sync with
# .claude/hooks/injection-gate-webfetch.sh case statement.
case "$HOST" in
  anthropic.com|www.anthropic.com|docs.anthropic.com|support.anthropic.com|console.anthropic.com)
    exit 0 ;;
  code.claude.com|platform.claude.com|claude.com|www.claude.com)
    exit 0 ;;
  augatho.com|*.augatho.com)
    exit 0 ;;
esac

# Reconstruct a usable URL for the suggestion message.
case "$URL_PART" in
  http://*|https://*) FULL_URL="$URL_PART" ;;
  *)                  FULL_URL="https://$URL_PART" ;;
esac

cat >&2 <<MSG
BLOCKED: raw curl/wget against non-allowlisted host.

  Host: ${HOST}

Use safe-fetch instead — the fetch runs inside a Docker-isolated
sandbox and the response is returned wrapped in <UNTRUSTED-WEB> tags:

  safe-fetch ${FULL_URL}

If the URL is genuinely trustworthy (first-party docs, your own
infra), extend the allowlist in BOTH files:

  ~/.claude/hooks/injection-gate-bash.sh
  ~/.claude/hooks/injection-gate-webfetch.sh

See https://github.com/sharkyger/claude-code-prompt-injection-gate
for the allowlist syntax and threat model.
MSG
exit 2
