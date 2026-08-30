# safe-fetch:latest — Layer-1 isolated fetch+sanitize container.
#
# Goal: download <url>, run the Layer-2 sanitizer, write the wrapped
# UNTRUSTED-WEB envelope to stdout, exit. The host invokes this image
# with --cap-drop=ALL --read-only --network=bridge --user nobody (etc.)
# — see src/safe_fetch/cli.py for the full hardened argv.
#
# The container itself is a fallback layer of defense. The flags
# enforced by the CLI wrapper are the real isolation; this image just
# avoids carrying anything the wrapper can't kill at runtime (no shell
# besides /bin/sh, no curl, no package manager artifacts after install).

FROM python:3.12-alpine

# Sanitizer deps. Both are PURE PYTHON, so this image now carries no native
# extension, no libxml2/libxslt runtime libs, and no gcc/musl-dev build
# toolchain at all. A compiler inside a sandbox image is attack surface the
# CLI's runtime flags cannot take away.
#
# Exact-pin must stay in lockstep with pyproject.toml so the host and the
# in-container install resolve to the same parsed tree. ENFORCED by
# tests/test_docker_pin_lockstep.py — Dependabot bumps pyproject.toml and
# cannot reach this line, so the drift is silent without a test that fails.
#
# soupsieve is pinned because it is LOAD-BEARING, not incidental: every
# hidden / off-screen element strip in sanitizer.py goes through
# soup.select(), so its selector engine decides what is removed. Until now it
# was an unpinned transitive of bs4, resolved independently on host and image.
RUN pip install --no-cache-dir 'beautifulsoup4==4.15.0' 'soupsieve==2.9.2'

WORKDIR /app

# Build context is the repo root (so the sanitizer module can be
# vendored without duplication). The accompanying build.sh sets the
# context explicitly.
COPY docker/entrypoint.py /app/entrypoint.py
COPY src/safe_fetch/sanitizer.py /app/sanitizer.py

# Run as a non-root user. The CLI wrapper additionally passes
# --user nobody at run-time, but baking it in here is belt+braces.
RUN adduser -D -H -s /sbin/nologin fetcher
USER fetcher

ENTRYPOINT ["python3", "/app/entrypoint.py"]
