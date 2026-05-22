# safe-fetch

Docker-isolated URL fetcher with a Layer-2 prompt-injection sanitizer
for LLM agents.

## What it does

When an AI agent (Claude Code, a custom LangChain agent, your own
script) fetches a webpage and reads the result, the page's text gets
treated as trusted context. **Indirect prompt injection** turns "I
read a webpage" into "the webpage wrote my next command." Invisible
Unicode, hidden HTML, base64 payloads, fake LLM delimiters,
homoglyph-substituted prose — none of those tells survive a
sanitizer that knows about them.

`safe-fetch <url>` fetches the page inside a hardened Docker
container, runs a sanitizer that strips known injection vectors, and
returns the result wrapped in an untrusted-content envelope tag so the
calling agent treats the body as data, not instructions. The wrap
also neuters any literal envelope-tag sequence appearing inside the
fetched content (envelope-breakout defense).

## How to use it

Two surfaces: the CLI directly, and Claude Code.

**Directly from your shell:**

```bash
safe-fetch https://example.com
```

Output is the sanitized page wrapped in an untrusted-content envelope.
Pipe it to a file, to your own agent, or to anything else that
consumes URL text.

**From inside Claude Code:** after installing the hooks (see
[Quick start](#quick-start) below), name `safe-fetch` explicitly in
your prompt to invoke the full Docker-isolated pipeline:

> Please use `safe-fetch` to fetch https://example.com/article and
> summarize what's there.

Or use the explicit Bash form:

> Please run `safe-fetch https://example.com/article` via Bash and
> show me the output.

Naming the tool guarantees the request flows through the container
isolation + sanitizer chain.

## Quick start

```bash
brew install sharkyger/tap/safe-fetch
safe-fetch https://example.com
```

That prints the sanitized page to stdout, wrapped in the untrusted-
content envelope.

For Claude Code users — install the gating hooks and slash commands:

```bash
safe-fetch --install-claude-hooks
```

This writes hooks, five operator slash commands, and a CLAUDE.md
rule snippet into `~/.claude/` idempotently. See
[Claude Code companion](#claude-code-companion) below.

## How to verify it's actually running

The simplest receipt: a successful `safe-fetch` returns the sanitized
page bracketed by untrusted-content envelope tags. If you see the
envelope, the container fired and the sanitizer ran.

For visual confirmation in a side terminal, the Docker events stream
is more reliable than `docker ps` (containers exit with `--rm` faster
than you can switch windows):

```bash
docker events --filter type=container --filter image=safe-fetch:latest \
  --format '{{.Time}} {{.Action}} {{.ID}}'
```

Then in another terminal:

```bash
safe-fetch https://example.com
```

You'll see a `start` event followed by a `die` event a few seconds
later. `docker ps -a --filter ancestor=safe-fetch:latest` also shows
recently-exited containers with their lifetimes.

### Multi-subagent + concurrent isolation

Each subagent invoking `safe-fetch` gets its own ephemeral container.
N concurrent safe-fetch calls produce N concurrent containers, each
fully isolated. Confirm via the events stream — parallel invocations
emit `start` events within milliseconds of each other and both `die`
events come AFTER both `start`s.

## Requirements

- **Docker** — required. The container is the isolation layer. If
  Docker isn't running, `safe-fetch` exits with a loud install hint
  instead of silently degrading. Corporate / no-Docker environments
  are out of scope for v1.
- **macOS or Linux**. Tested on Apple Silicon + Intel; should work on
  Linux but the `host.docker.internal` resolution in the live smoke
  test currently assumes Docker Desktop.

## The threat

Demonstrated, not theoretical:

- **CVE-2025-59536** — RCE via Claude Code project files (Check Point)
- **CVE-2026-21852** — API token exfiltration via Claude Code project files (Check Point)
- Lasso Security's *"The Hidden Backdoor in Claude Coding Assistant"*
- Anthropic's Nov 2025 prompt-injection-defenses paper acknowledges a
  1% attack success rate as "meaningful risk" but ships no developer
  tooling alongside it.

`safe-fetch` ships the developer tooling.

## What the sanitizer strips

| Vector | Caught? |
|--------|---------|
| Zero-width Unicode (U+200B, U+200C, U+200D, etc.) | yes |
| Bidi override characters (U+202E, U+202D) | yes |
| Tag characters (U+E0000-E007F) | yes |
| Variation selectors | yes |
| NFKC-normalizable homoglyphs (Cyrillic 'а' in Latin) | yes |
| `<script>`, `<style>`, `<noscript>` content | yes |
| HTML comments | yes |
| Off-screen CSS (`position: absolute; left: -9999px;`) | yes |
| Same-color CSS (white-on-white prose) | yes |
| Base64-encoded instruction payloads | yes |
| Fake LLM delimiters (`<\|im_start\|>`, `[INST]`, etc.) | yes |
| Semantic prose with no Unicode/HTML tells | **not in v1** (see Limitations) |

## Architecture

```
host                 │  container (--cap-drop=ALL --read-only
                     │             --network=bridge --user nobody)
                     │
safe-fetch <url>     │
   │                 │
   ├── validate URL  │
   ├── check Docker  │
   └── docker run ───┼──> fetch URL via urllib
                     │     ├── 5 MB raw cap
                     │     └── 15 s timeout
                     │   sanitize content
                     │     ├── strip invisible Unicode
                     │     ├── NFKC normalize
                     │     ├── strip <script>, <style>, comments
                     │     ├── strip hidden CSS prose
                     │     ├── decode base64 payloads (flag, don't execute)
                     │     ├── strip fake LLM delimiters
                     │     ├── escape inner envelope-tag sequences
                     │     └── cap output at 20 KB
                     │   wrap in untrusted-content envelope
                     │   write to stdout
                     │
   sanitized stdout <┘
```

The full hardened docker-run flag set lives in
[`src/safe_fetch/cli.py`](src/safe_fetch/cli.py) `DOCKER_FLAGS`. Every
flag is asserted by `tests/test_safe_fetch_cli.py` — a missing or
relaxed flag is a security regression.

## Claude Code companion

`safe-fetch --install-claude-hooks` writes the
[claude-code-prompt-injection-gate](https://github.com/sharkyger/claude-code-prompt-injection-gate)
companion into `~/.claude/`:

- **4 hooks** that gate WebFetch, Bash (curl/wget), Agent (subagent
  results), and Write/Edit (protected paths)
- **5 operator slash commands** (`/save-memory`, `/save-rule`,
  `/edit-skill`, `/edit-settings`, `/edit-hook`) that produce
  single-use markers authorizing writes to protected destinations
- **CLAUDE.md snippet** documenting the Layer-4 system rule

After install, fetches and shell commands run through an allowlist-
aware gating layer. Subagent results carry an untrusted-source marker.
Writes to your operator-controlled files (CLAUDE.md, settings, hooks,
skills, project memory) are gated behind a single-use marker that only
the operator slash commands can produce.

For the full architecture and threat model, see the
[claude-code-prompt-injection-gate](https://github.com/sharkyger/claude-code-prompt-injection-gate)
companion repo.

### Uninstall

```bash
safe-fetch --uninstall-claude-hooks
```

Removes everything the installer wrote, leaves untouched config
intact.

## Allowlist syntax

Edit `~/.claude/hooks/injection-gate-webfetch.sh` and
`~/.claude/hooks/injection-gate-bash.sh`. Both files contain a
`case "$HOST" in ... esac` block; add your domains as new cases:

```bash
case "$HOST" in
  anthropic.com|*.anthropic.com)        exit 0 ;;
  claude.com|*.claude.com)              exit 0 ;;
  yourcompany.com|*.yourcompany.com)    exit 0 ;;   # add this
esac
```

Edit both files — the WebFetch hook gates `WebFetch`, the Bash hook
gates raw `curl`/`wget`. Allowlist must match in both for a domain to
pass through both surfaces.

## Troubleshooting

**"safe-fetch: Docker is not available."** — Docker Desktop isn't
running. Start it and retry. On Linux, ensure the daemon is up
(`sudo systemctl start docker`).

**"safe-fetch: image not found."** — The `safe-fetch:latest` image
isn't built locally yet. Run `docker/build.sh` from the source
checkout, or wait for the brew formula to bake it during install.

**Marker prompt after a memory write** — Expected. Writes to protected
paths (`CLAUDE.md`, hooks, skills, settings, project-memory) require
an operator-issued slash command (`/save-memory`, `/save-rule`,
`/edit-skill`, `/edit-settings`, `/edit-hook`) to authorize a
single-use marker. Run the slash command, then retry the write.

**Allowlist too narrow / too wide** — Edit the `case` block in both
hook files (see Allowlist syntax above). Re-run any test command
that previously got blocked.

## Development

```bash
git clone https://github.com/sharkyger/safe-fetch
cd safe-fetch
pip install -e ".[dev]"

# Build the Docker image
docker/build.sh

# Run tests
pytest

# Lint
ruff check
```

## License

MIT — see [LICENSE](LICENSE).

Sanitizer logic ported from [timstarkk/mcp-safe-fetch](https://github.com/timstarkk/mcp-safe-fetch)
(MIT, © 2025 Tim Stark). See [NOTICE](NOTICE) for the upstream
attribution and license text.
