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

## Quick start

```bash
brew install sharkyger/tap/safe-fetch
safe-fetch https://example.com
```

That prints the sanitized page to stdout, wrapped in the untrusted-
content envelope.

For Claude Code users — install the gating hooks and slash commands
that route every fetch through `safe-fetch`:

```bash
safe-fetch --install-claude-hooks
```

This writes hooks, five operator slash commands, and a CLAUDE.md
rule snippet into `~/.claude/` idempotently. See
[Claude Code companion](#claude-code-companion) below.

### Important: tell Claude Code to USE safe-fetch

After install, Claude Code will still default to its built-in `WebFetch`
tool for "fetch this URL"-style requests — that's faster (no Docker
spin-up) but doesn't isolate the content. The hooks warn you when
WebFetch hits a non-allowlisted host, but they don't auto-reroute it.

**To actually invoke Docker-isolated fetching, name the tool in your
prompt:**

> Please use `safe-fetch` to fetch https://example.com/article and
> summarize what's there.

Or use the explicit Bash form:

> Please run `safe-fetch https://example.com/article` via Bash and
> show me the output.

If you just say "fetch this URL," Claude will pick the path it
considers easiest — usually WebFetch. The container won't fire. The
allowlist warning + sanitizer-wrapped subagent envelopes still apply,
but you don't get the Docker-isolated fetch + Layer-2 sanitizer pass.

See [How to verify it's actually running](#how-to-verify-its-actually-running)
below for the full trust-gradient table and proof patterns.

## How to verify it's actually running

Two things confuse first-time users:

1. **`docker ps` looks empty** — `safe-fetch` uses `--rm`, so the
   container vanishes the moment the fetch completes (usually
   2-5 seconds total). By the time you switch terminals, it's gone.

2. **Asking your agent to "fetch a URL" might not fire Docker** —
   because there are multiple paths to "fetch", and only one of them
   uses `safe-fetch`. See the trust gradient below.

### The real receipt: the envelope

You don't need to catch Docker live. The output itself proves the
container ran:

```bash
safe-fetch https://example.com
```

If the output starts with `<UNTRUSTED-WEB url="...">` and ends with
the matching close tag, the container fired, the sanitizer ran, and
your agent will treat the body as data. **Nothing else produces that
envelope** — not WebFetch, not raw curl, not any other path.

### The trust gradient (what does and doesn't fire Docker)

`safe-fetch --install-claude-hooks` configures a layered defense.
Docker isolation is reserved for content from non-allowlisted
origins, not used for every fetch (overhead would be ~3s per call,
unworkable for first-party docs):

| Path | What happens | Docker fires? |
|---|---|---|
| Claude Code's `WebFetch` tool | Warning if non-allowlisted, otherwise silent | **No** — by design, WebFetch never reroutes to Docker |
| Bash `curl`/`wget` to allowlisted host (Anthropic, your domains) | Passes silently | No |
| Bash `curl`/`wget` to non-allowlisted host | **BLOCKED**; agent told to use `safe-fetch` instead | Only after the agent re-issues as `safe-fetch <url>` |
| Explicit `safe-fetch <url>` (CLI or via Bash tool) | Always Docker | **Yes**, every time |

So to *demonstrate* Docker firing, ask your agent to use `safe-fetch`
explicitly, not "fetch this URL." Example prompt:

> Please run `safe-fetch https://en.wikipedia.org/wiki/Prompt_injection`
> via the Bash tool and show me the output.

### Catching containers live (if you really want to)

For visual confirmation in a side terminal, the Docker events stream
is more reliable than `docker ps` because it captures every start/stop
with a timestamp, even after the container is gone:

```bash
docker events --filter type=container --filter image=safe-fetch:latest \
  --format '{{.Time}} {{.Action}} {{.ID}}'
```

Then in another terminal:

```bash
safe-fetch https://example.com
```

You'll see a `start` event followed by a `die` event a few seconds
later. After the fact, `docker ps -a --filter ancestor=safe-fetch:latest`
also shows recently-exited containers with their lifetimes.

### Multi-subagent + concurrent Docker

Each subagent invoking `safe-fetch` gets its own ephemeral container.
N subagents fetching in parallel → N concurrent containers, each with
its own `--cap-drop=ALL`, `--read-only`, `--network=bridge` isolation.
Verify with the events stream above: two parallel safe-fetch invocations
produce two `start` events within milliseconds of each other and both
`die` events come AFTER both `start`s.

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

After install, every WebFetch URL is checked against the allowlist
(first-party Anthropic + your domains pass; everything else gets a
warning). Raw `curl`/`wget` against non-allowlisted hosts is
auto-rewritten to `safe-fetch`. Subagent results are wrapped in an
untrusted-subagent envelope. Writes to `CLAUDE.md`,
`.claude/settings.json`, `.claude/hooks/*.sh`, skill files, or
project-memory files are gated behind a single-use marker that only
the operator slash commands can produce.

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
