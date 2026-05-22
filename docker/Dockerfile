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

# Install sanitizer deps. lxml needs libxml2/libxslt at runtime.
RUN apk add --no-cache libxml2 libxslt \
 && apk add --no-cache --virtual .build-deps gcc musl-dev libxml2-dev libxslt-dev \
 && pip install --no-cache-dir 'beautifulsoup4==4.12.3' 'lxml==5.3.0' \
 && apk del .build-deps

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
