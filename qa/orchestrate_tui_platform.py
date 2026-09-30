#!/usr/bin/env python3
"""Portable timing and source-permission evidence for the native QA matrix."""

import argparse
from pathlib import Path
import stat
import time


def monotonic_ms():
    return time.monotonic_ns() // 1_000_000


def elapsed_ms(started):
    elapsed = monotonic_ms() - started
    if started < 0 or elapsed < 0:
        raise ValueError(
            "start must be a nonnegative monotonic timestamp no later than now"
        )
    return elapsed


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("now-ms")
    elapsed = commands.add_parser("elapsed-ms")
    elapsed.add_argument("started", type=int)
    mode = commands.add_parser("source-mode")
    mode.add_argument("path", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "now-ms":
            print(monotonic_ms())
        elif args.command == "elapsed-ms":
            print(elapsed_ms(args.started))
        else:
            print(f"source_mode={stat.S_IMODE(args.path.stat().st_mode):o}")
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
