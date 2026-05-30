# Changelog

All notable changes to safe-fetch are recorded here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning
follows [SemVer](https://semver.org/), with the project-specific
pre-stable rule that `v0.x.y` precedes the first reliably-tested
stable `v1.0`.

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
