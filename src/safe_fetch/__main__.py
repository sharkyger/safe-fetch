"""Allow ``python -m safe_fetch <url>``."""

from safe_fetch.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
