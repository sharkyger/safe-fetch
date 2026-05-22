#!/bin/bash
# Build the safe-fetch:latest Docker image from the repo root.
#
# Build context is the repo root so the Dockerfile can vendor the
# sanitizer module from src/safe_fetch/ without duplication.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

cd "$REPO_ROOT"

exec docker build \
    -t safe-fetch:latest \
    -f docker/Dockerfile \
    .
