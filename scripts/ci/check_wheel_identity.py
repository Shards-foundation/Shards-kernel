#!/usr/bin/env python3
"""Validate built Shards-Kernel wheels without importing from the source checkout."""

import sys
import zipfile
from pathlib import Path


def main() -> int:
    wheel_paths = [Path(value) for value in sys.argv[1:]]
    if not wheel_paths:
        raise SystemExit("Provide one or more wheel paths")

    for path in wheel_paths:
        if not path.is_file():
            raise SystemExit("Wheel not found: {}".format(path))
        if not path.name.startswith("shards_kernel-"):
            raise SystemExit("Unexpected wheel distribution name: {}".format(path.name))
        with zipfile.ZipFile(path) as wheel:
            members = set(wheel.namelist())
        if "shards_kernel/__init__.py" not in members:
            raise SystemExit("Missing canonical shards_kernel namespace in {}".format(path))
        if "shards_kernel/api.py" not in members:
            raise SystemExit("Missing public API in {}".format(path))
        if any(name.startswith("kernels/") for name in members):
            raise SystemExit("Legacy kernels namespace leaked into {}".format(path))
        print("Verified wheel namespace: {}".format(path))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
