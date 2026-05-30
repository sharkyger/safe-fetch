# Changelog

All notable changes to safe-fetch are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning
follows [SemVer](https://semver.org/), with the project-specific
pre-stable rule that `v0.x.y` precedes the first reliably-tested
stable `v1.0`.

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
  `lxml` in `pyproject.toml` now pin to `==4.12.3` and `==5.3.0` —
  identical to the Dockerfile pins — so a host-side install and the in-
  container install resolve to byte-identical parsed-tree behavior, and a
  compromised maintainer account cannot push a new patch into installs.
  Dependabot tracks future bumps.

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

- Removed maintainer-personal domain `augatho.com` from the default
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
