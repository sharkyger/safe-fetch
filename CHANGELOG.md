# Changelog

All notable changes to safe-fetch are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning
follows [SemVer](https://semver.org/), with the project-specific
pre-stable rule that `v0.x.y` precedes the first reliably-tested
stable `v1.0`.

## [Unreleased]

### Documentation

- Added a worked **Brave Search** example to the "Searching the web"
  section of the README (URL template + `X-Subscription-Token` header,
  key as a placeholder), noting that Brave's header auth keeps the key
  out of the result envelope.

### Changed

- Bumped `beautifulsoup4` from 4.14.3 to 4.15.0, with the
  `docker/Dockerfile` pin updated in lockstep per the exact-pin
  contract (CVE-clean, past the freshness hold).
- Bumped SHA-pinned GitHub Actions: `actions/checkout` v6.0.2 → v6.0.3
  and `github/codeql-action` v4.36.0 → v4.36.2.

## [0.3.0] - 2026-06-07

### Added

- Web-search support. `safe-fetch search "<query>"` runs a web search
  and returns the results wrapped in the same `<UNTRUSTED-WEB>` envelope
  as a fetched page — search results are untrusted data, run through the
  identical hardened-container fetch + Layer-2 sanitizer path. safe-fetch
  bundles no search provider and no allowlist: the command ships empty
  and fails closed until the user configures a backend.
- `safe-fetch search --setup`, a one-time interactive wizard that
  collects a URL template (with a `{query}` placeholder) and an optional
  auth header, writes `~/.config/safe-fetch/search.json` with owner-only
  (0600) permissions, and can run a verification search. Power users can
  set `SAFE_FETCH_SEARCH_URL` / `SAFE_FETCH_SEARCH_HEADER` in the
  environment instead (these take precedence over the file).
- The query is percent-encoded before substitution into the template,
  and the optional auth header is sent as an in-container request header
  (never interpolated into the URL), so a provider key never reaches the
  result envelope. Control characters in a forwarded header are stripped
  at the container boundary to prevent header injection.
- Credential hygiene for the auth header: it is refused over cleartext
  `http` (loopback hosts excepted), stripped on cross-origin redirects so
  it is never resent to another host, and a malformed header value fails
  loudly rather than sending the request unauthenticated. The URL template
  is host-pinned — the `{query}` placeholder may appear only in the path
  or query string, never in the scheme, host, port, or fragment.

### Verification

- 241 pytest tests pass (3.10/3.11/3.12). New coverage: `tests/test_search.py`,
  `tests/test_search_cli.py`, `tests/test_search_setup.py`, plus
  search-auth-header cases in `tests/test_docker_entrypoint.py`,
  including an envelope-breakout regression on the query→URL boundary.

## [0.2.1] - 2026-06-04

### Security

- Hardened output-encoding of the untrusted-content envelope header.
  Attacker-influenced values placed into the header are now
  HTML-escaped and stripped of control characters before
  interpolation, so a header value can never alter the surrounding
  envelope structure. Defense-in-depth; no user action required.

### Changed

- Broadened sanitizer defense-in-depth coverage: `visibility:collapse`
  now joins the hidden-element selectors; the base64 instruction-scan
  window was widened so multi-hundred-byte encoded payloads are
  decoded and scanned; suspicious-URL detection now inspects the URL
  path (not just the query string) for exfil-shaped segments; and the
  LLM-delimiter set gained reserved chat-template tokens (Llama-3
  header/turn markers, ChatML separator) and the `System:` turn
  marker. New regression coverage in
  `tests/test_sanitizer.py::TestDefenseInDepthGaps`.

## [0.2.0] - 2026-05-31

### Theme

**Positioning release.** Code surface stays minimal (one new env-var
passthrough). Docs/scope surface expands to declare what `safe-fetch`
is, what it isn't, and which tools own the lanes outside the carve-out
list. Goal: future contributors and downstream consumers don't ask
"why don't you add X?" when X is in someone else's lane.

### Added

- **`HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` honoring.** When any of
  these env vars are set on the host, they're forwarded into the
  isolated container via `-e VAR=value` so the in-container `urllib`
  honors them. Composes with proxy-based scanners like
  [pipelock](https://github.com/luckyPipewrench/pipelock) without
  `safe-fetch` becoming one. **Zero behavior change when none are
  set** — the docker argv is byte-identical to v0.1.x in that case.
  Empty-string values are treated as unset. Forwarding order is
  stable (`HTTPS_PROXY`, `HTTP_PROXY`, `NO_PROXY`) so the docker
  argv is deterministic for tests and audit. The URL stays the
  final positional arg, so the v0.1.x security invariant ("flag
  injection via URL is impossible") still holds. 7 new regression
  tests in `tests/test_safe_fetch_cli.py::TestProxyPassthrough`.
- **`docs/SCOPE.md`** — tracked, canonical scope statement + 5 hard
  carve-outs. Mirrors the README's Scope section as the
  authoritative form.
- **README "What `safe-fetch` does NOT catch" subsection** inside the
  Threat model section. Names the inherent boundary: the Bash hook is
  regex on the agent's command text, so tools that fetch URLs
  internally (`brew`, `git`, `gh`, `pip`, `npm`, `apt`, `dnf`, …)
  bypass the hook by design. Points to pipelock for network-layer
  scanning when wanted.
- **README "Alternative approaches" section.** Acknowledges
  [pipelock](https://github.com/luckyPipewrench/pipelock) and
  [vault](https://github.com/vaultmcp/vault) as different design
  philosophies rather than competitors. Each gets a one-liner of
  what they're good at and when to reach for them.
- **README "Scope" section.** One-liner + the 5 hard carve-outs
  (no blockchain, no DLP, no extra process containment, no
  LLM-runtime detection, no multi-protocol scanning). Mirrors
  `docs/SCOPE.md`.

### Changed

- `safe-fetch/0.2.0` USER_AGENT. Tracks the package version (the
  existing `TestUserAgentMatchesPackageVersion` regression test
  catches drift).

### Verification

- 133 pytest tests pass (was 126 at v0.1.2; +7 new proxy
  passthrough tests). The new regression class exercises (a) no
  proxy vars → no `-e` flags, (b) `HTTPS_PROXY` only, (c) all three
  set with stable order, (d) values preserved verbatim (no
  mangling), (e) proxy flags positioned before image (so they go to
  docker, not the entrypoint), (f) URL remains the final positional
  arg, (g) empty-string proxy value is treated as unset.
- mypy clean on 6 source files.
- shellcheck clean on 4 bundled hooks + `docker/build.sh`.

## [0.1.2] - 2026-05-30

### Security

- **URL-userinfo bypass in Bash hook.** A request like
  `https://anthropic.com@evil.com/path` parses per RFC 3986 as
  `userinfo=anthropic.com`, `host=evil.com`. The previous host extraction
  stripped only the scheme and path, leaving `anthropic.com` as the matched
  HOST — so the allowlist let the request through while the underlying
  fetcher actually hit `evil.com`. Fixed in `injection-gate-bash.sh` by
  stripping the `userinfo@` prefix and any `:port` between scheme-strip and
  path-strip; the userinfo strip is path-aware (`[^@/?#]*@`) so a stray `@`
  in a path/query/fragment does not trigger false stripping. Regression
  tests in `tests/test_injection_gate_bash_hook.py` cover five userinfo
  variants (scheme-prefixed, with-path, user:pass, scheme-less, empty-
  password). Surfaced by the 2026-05-30 Tier 1 baseline review (CodeRabbit
  CRITICAL); confirmed by Mistral Vibe assessment.
- **Stage 2 URL extraction in Bash hook now prefers scheme-prefixed URLs.**
  Previous regex first-match could pick non-URL host-shaped tokens like
  `file.bin` from `-o /tmp/file.bin`. Now `https?://[^[:space:]]+` is tried
  first; scheme-less host regex is the fallback and includes optional
  userinfo so the bypass above cannot evade the strip by simply omitting
  the scheme.
- **In-container fetcher re-validates every redirect hop.** `_fetch` in
  `docker/entrypoint.py` previously used `urllib.request.urlopen` directly,
  which followed redirects with the stdlib's default `HTTPRedirectHandler`.
  A 30x could redirect a sanctioned http/https request into a URL that
  failed our host-side contract (empty host, exotic scheme via a future
  urllib relaxation, etc.). Added `_ValidatingRedirectHandler` that calls
  `_validate(newurl)` on every hop and converts a validation failure to a
  403 HTTPError so the existing error path reports it cleanly.
- **GHA actions pinned to commit SHAs.** `.github/workflows/ci.yml` no
  longer uses mutable `@v4` / `@v5` tags — a hostile takeover of
  `actions/checkout` or `actions/setup-python` cannot retroactively change
  what CI runs. All new workflows (`codeql.yml`, `gitleaks.yml`) follow the
  same pinning rule.
- **`persist-credentials: false` on every checkout step.** The default
  (`true`) writes `GITHUB_TOKEN` to `.git/config` after checkout — a
  credential-exfiltration surface for any subsequent step that reads
  `.git/config` (malicious dep install, build script touching git, etc.).
  Now explicitly disabled.
- **Runtime deps exact-pinned to match Dockerfile.** `beautifulsoup4` and
  `lxml` in `pyproject.toml` now pin to `==4.14.3` and `==6.1.1` —
  identical to the Dockerfile pins — so a host-side install and the in-
  container install resolve to byte-identical parsed-tree behavior, and a
  compromised maintainer account cannot push a new patch into installs.
  The `lxml 6.1.1` bump (up from `5.3.0`) closes `PYSEC-2026-87`
  (caught by `pip-audit` in the new static-analysis CI job, fix only
  available in the 6.1.0+ line). Dependabot tracks future bumps.

### Fixed

- **Installer `_data_root()` returned a Path from a closed context
  manager.** For zip/wheel-loaded packages the extracted temp dir was
  cleaned up before any caller read the file. Loose-on-disk pip layouts
  did not hit the bug because `as_file()` is a no-op there. Fixed via a
  module-level `ExitStack` that keeps the context manager alive for the
  process lifetime; the resolved Path is cached so subsequent callers do
  not enter a fresh context.
- **Installer snippet end-marker search now anchored after BEGIN.**
  `_strip_snippet()` previously used unanchored `content.index(END_MARK)`,
  so a stray END marker quoted earlier in the file could match before
  BEGIN and leave the real snippet in place. Now
  `content.index(END_MARK, begin)`.
- **Installer hook-prefix filter is now path-boundary aware.**
  `_unmerge_settings()` previously used `startswith(hooks_prefix)`, which
  also matched sibling paths like `<target>/hooks-backup/...` and
  incorrectly swept their entries on uninstall. Now anchored on
  `hooks_prefix + os.sep` so only entries under the managed `hooks/`
  directory match.
- **Installer reinstall now heals stripped exec bits.** When bytes match
  the bundled source but the file's executable bits were stripped
  externally (`chmod -x`), reinstall previously reported "skip — already
  installed" without restoring `+x`. Now treats as "update" and `chmod`
  restores the mask.
- **`USER_AGENT` follows `__version__` programmatically (via test).**
  `docker/entrypoint.py` `USER_AGENT` and `safe_fetch.__version__` must
  stay in sync — `tests/test_docker_entrypoint.py::TestUserAgentMatchesPackageVersion`
  trips on drift.

### Added (tooling floor — per fleet-rule `professional_coding_tooling_floor`)

- `.coderabbit.yaml` with `profile: assertive` and path-instructions that
  treat allowlist relaxation, regex weakening, and fail-open paths in
  `injection-gate-*.sh` as security-critical.
- `.github/workflows/codeql.yml` — Python SAST, weekly schedule.
- `.github/workflows/gitleaks.yml` — secret scanning, full-history on PR.
- `.github/dependabot.yml` — pip + github-actions, weekly Monday 07:00.
- `.pre-commit-config.yaml` — ruff + shellcheck + markdownlint + safety
  hooks (trailing-whitespace, end-of-file-fixer, check-yaml, check-json,
  check-merge-conflict, check-added-large-files, detect-private-key).
- `.markdownlint.json` with lenient defaults.
- CI now runs `mypy`, `bandit`, `pip-audit`, `ruff format --check`, and
  `shellcheck` across the bundled hooks + `docker/build.sh`.
- Dev deps in `pyproject.toml`: `mypy>=1.10`, `bandit>=1.7`, `pip-audit>=2.7`.
- `[tool.mypy]` config in `pyproject.toml`: `check_untyped_defs`,
  `no_implicit_optional`, `strict_equality`, `warn_unreachable`,
  `warn_unused_ignores`.

### Changed

- **README restructured per fleet rule `readme_usage_before_install`.**
  Threat-model section now sits above USAGE — security-conscious readers
  evaluate "what attack does this prevent" first. Sanitizer-vector table
  + four-layer defense model + honest limitations all land in one place.
- **`safe-fetch/0.1.2` USER_AGENT.** Tracks the package version.

### Verification

- 125 pytest tests pass (up from 104 at v0.1.1; +21 new regression tests
  across bash hook, in-container fetcher, installer, version sync).
- `mypy` clean on 6 source files.
- `shellcheck` clean on 4 bundled hooks + `docker/build.sh`.
- Independent Mistral Vibe assessment 2026-05-30 confirmed Layer-1
  container hardening as "enterprise-grade" and flagged the URL-userinfo
  bypass as the headline CRITICAL — addressed in commit `7b681ef` on this
  release.

## [0.1.1] - 2026-05-30

### Changed

- **Version-policy reset.** v1.0.0 (2026-05-22) and v1.0.1
  (rtk-wrapped curl/wget hook fix) were tagged before the project's
  pre-stable versioning rule (pre-stable = `v0.x.y`) was adopted on
  2026-05-29. safe-fetch is still in open beta: the corpus is small,
  the API surface may shift, and the freshness-hold delay debate is
  unresolved. `v0.1.1` is the honest label.
- `README.md` declares pre-stable status near the top.
- `Development Status` classifier in `pyproject.toml` moves from
  `5 - Production/Stable` to `4 - Beta`.
- `docker/entrypoint.py` `USER_AGENT` follows the version (was stale
  at `safe-fetch/1.0`).

### Fixed

- Removed a maintainer-personal domain from the default
  Bash-hook allowlist. The domain was committed in the initial
  scaffold and shipped through v1.0.x; it leaks an OSS-irrelevant
  allowlist entry to every install. The companion WebFetch hook never
  carried it, so this also resolves the documented "allowlists must
  match across both hook surfaces" inconsistency. (Surfaced by the
  first-run full-codebase code review.)

### Migration for downstream users

The only known consumer is `sharkyger/homebrew-tap`'s `safe-fetch`
formula. Reinstall:

```bash
brew uninstall safe-fetch
brew install sharkyger/tap/safe-fetch
```

or `brew upgrade safe-fetch` after the formula PR lands.

The v1.0.0 and v1.0.1 git tags remain published; the homebrew formula
stops referencing them.

## Prior releases

CHANGELOG starts at v0.1.1. The two prior releases are documented on
their GitHub release pages:

- [v1.0.1](https://github.com/sharkyger/safe-fetch/releases/tag/v1.0.1) — 2026-05-28 — Bash hook catches rtk-wrapped `curl`/`wget`.
- [v1.0.0](https://github.com/sharkyger/safe-fetch/releases/tag/v1.0.0) — 2026-05-22 — Initial public release.
