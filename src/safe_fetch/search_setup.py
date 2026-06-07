"""Interactive setup wizard for ``safe-fetch search``.

``safe-fetch search --setup`` walks the user through configuring a
search backend in one sitting: paste a URL template, optionally paste an
auth header (read without echo), optionally run a real test search, and
the config is written with owner-only permissions. There is no bundled
provider — the wizard is the easy front door for the user's own choice.

I/O is injected (``input_fn`` / ``getpass_fn`` / ``run_test_fn``) so the
flow is unit-testable without a TTY or Docker.
"""

from __future__ import annotations

import getpass as _getpass
from collections.abc import Callable
from typing import TextIO

from safe_fetch import search

_MAX_TEMPLATE_ATTEMPTS = 5
# Benign placeholder query used only for the optional verification search.
_TEST_QUERY = "test"


def _default_test_search(url: str, auth_header: str | None) -> int | None:
    """Run a real search through the container; ``None`` if Docker absent."""
    from safe_fetch import cli

    if not cli._check_docker():
        return None
    cmd = cli._build_search_docker_command(url, auth_header=auth_header)
    return cli.subprocess.run(cmd, check=False).returncode


def run_setup(
    *,
    dry_run: bool = False,
    input_fn: Callable[[str], str] = input,
    getpass_fn: Callable[[str], str] = _getpass.getpass,
    run_test_fn: Callable[[str, str | None], int | None] | None = None,
    out: TextIO | None = None,
) -> int:
    """Collect a search backend config and write it. Returns an exit code."""

    def w(msg: str = "") -> None:
        print(msg, file=out)

    w("safe-fetch search setup")
    w()
    w("Enter your search provider's URL, putting {query} where the search")
    w("words go. Example: https://api.example.com/search?q={query}")
    w("safe-fetch ships with no provider — this is your choice.")

    template = ""
    for _ in range(_MAX_TEMPLATE_ATTEMPTS):
        template = input_fn("Search URL template: ").strip()
        terr = search.template_error(template)
        if terr is None:
            break
        w(f"  ! {terr}")
    else:
        w("Too many invalid attempts; aborting.")
        return 1

    w()
    w("Optional: an auth header your provider needs, e.g.")
    w("  X-Subscription-Token: <key>   or   Authorization: Bearer <key>")
    w("It is stored locally and sent as a request header (never put in the")
    w("URL or the result envelope). Leave blank if none. Input is hidden.")
    auth = getpass_fn("Auth header (blank = none): ").strip()
    auth_header = auth or None

    config = search.SearchConfig(url_template=template, auth_header=auth_header)

    answer = input_fn("Run a test search now to verify? [y/N]: ").strip().lower()
    if answer in ("y", "yes"):
        runner = run_test_fn or _default_test_search
        test_url = search.build_search_url(template, _TEST_QUERY)
        rc = runner(test_url, auth_header)
        if rc is None:
            w("  Docker not available — skipping the live test.")
        elif rc == 0:
            w("  Test search succeeded.")
        else:
            w(f"  Test search returned exit code {rc}; saving the config anyway.")

    result = search.save_config(config, dry_run=dry_run)
    if dry_run:
        w(f"[dry-run] would write {result.path}")
        return 0
    verb = "Updated" if result.kind == "update" else "Created"
    w(f"{verb} {result.path} (permissions 600).")
    w('Done. Try:  safe-fetch search "your question"')
    return 0
