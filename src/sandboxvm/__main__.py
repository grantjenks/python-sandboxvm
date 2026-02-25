"""Module entrypoint for `python -m sandboxvm`."""

from __future__ import annotations

import sys

from .preflight import assert_runtime_ready


def main() -> int:
    try:
        assert_runtime_ready()
    except RuntimeError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    print("sandboxvm runtime is ready.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
