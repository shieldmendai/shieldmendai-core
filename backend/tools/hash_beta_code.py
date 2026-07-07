#!/usr/bin/env python3
"""Prompt privately for a beta access code and print its SHA-256 hash."""

from __future__ import annotations

import getpass
import hashlib
import sys


def main() -> int:
    code = getpass.getpass("Beta access code: ")
    if not code:
        print("No code entered.", file=sys.stderr)
        return 1
    print(hashlib.sha256(code.encode("utf-8")).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
