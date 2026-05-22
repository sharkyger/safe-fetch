# Test Fixtures Attribution

The HTML fixtures in this directory are copied verbatim from
[timstarkk/mcp-safe-fetch](https://github.com/timstarkk/mcp-safe-fetch)
at commit `e82724c9b9535aff6c2cc102aa17abd16b726b96`.

License: MIT
Copyright (c) 2025 Tim Stark

They are used here as golden-file regression fixtures for the Python
port of the same sanitizer (`src/safe_fetch/sanitizer.py`).

## Refresh from upstream

```
git clone https://github.com/timstarkk/mcp-safe-fetch.git /tmp/mcp-safe-fetch-ref
git -C /tmp/mcp-safe-fetch-ref checkout e82724c9b9535aff6c2cc102aa17abd16b726b96
cp /tmp/mcp-safe-fetch-ref/test/fixtures/*.html tests/fixtures/
```

Bumping the pinned commit requires a fresh source audit of the
upstream sanitizer before adoption.
