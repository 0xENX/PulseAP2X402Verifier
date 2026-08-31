"""Fail when the official Pulse checker does not confirm a reproduction record."""

from __future__ import annotations

import argparse
import json
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    args = parser.parse_args()

    report = json.loads(args.report.read_text(encoding="utf-8"))
    if report.get("valid") is True and report.get("automatedChecksPassed") is True:
        print("Official Pulse reproduction checker confirmed all fixture results.")
        return 0

    errors = report.get("errors")
    if not isinstance(errors, list):
        errors = []
    print("Official Pulse reproduction checker rejected the record.")
    for error in errors:
        print(f"- {error}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
