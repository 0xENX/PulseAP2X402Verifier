"""Create the formal Pulse independent-reproduction record from evaluator output."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import subprocess
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path
from typing import Any


PULSE_COMMIT = "e06a6cbfe3ddb965c8fc70f50838f5014ec2038e"
PULSE_FIXTURE_SHA256 = "8f40be1bdc3d4458f758100e91b418b6a335c5d8d358723f118e2d3e1ad84ee0"
PUBLISHED_URL = "https://github.com/0xENX/PulseAP2X402Verifier/blob/main/evidence/reproduction.json"
COMMIT_PATTERN = re.compile(r"^[0-9a-f]{40}$")


def _current_commit() -> str:
    value = os.environ.get("GITHUB_SHA")
    if not value:
        value = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if not COMMIT_PATTERN.fullmatch(value):
        raise ValueError("The implementation commit must be a 40-character lowercase SHA-1")
    return value


def _dependencies() -> list[str]:
    names = ("ap2", "eth-account", "jwcrypto")
    return [f"{name}=={version(name)}" for name in names]


def _results(report: dict[str, Any]) -> list[dict[str, Any]]:
    raw_results = report.get("results")
    if not isinstance(raw_results, list) or len(raw_results) != 80:
        raise ValueError("The advanced report must contain exactly 80 case results")
    results: list[dict[str, Any]] = []
    seen: set[str] = set()
    for result in raw_results:
        if not isinstance(result, dict):
            raise ValueError("Every advanced result must be an object")
        case_id = result.get("case_id")
        consistent = result.get("consistent")
        failure_codes = result.get("failure_codes")
        if not isinstance(case_id, str) or not case_id or case_id in seen:
            raise ValueError("Every case result must have a distinct case_id")
        if not isinstance(consistent, bool) or not isinstance(failure_codes, list):
            raise ValueError(f"Invalid result shape for {case_id}")
        if not all(isinstance(code, str) and code for code in failure_codes):
            raise ValueError(f"Invalid failure code in {case_id}")
        seen.add(case_id)
        results.append({"id": case_id, "decision": "accept" if consistent else "reject", "failureCodes": failure_codes})
    return results


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    report = json.loads(args.report.read_text(encoding="utf-8"))
    if report.get("fixture_sha256") != PULSE_FIXTURE_SHA256 or report.get("cases") != 80:
        raise SystemExit("The advanced report does not identify the pinned 80-case Pulse fixture")

    record = {
        "recordVersion": "pulse-independent-reproduction/0.1",
        "performedAt": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "implementation": {
            "repositoryUrl": "https://github.com/0xENX/PulseAP2X402Verifier",
            "commit": _current_commit(),
            "language": "Python",
            "runtime": f"Python {platform.python_version()}",
            "command": "python -m pulse_ap2_x402_verifier.advanced pulse-corpus/fixtures/v0.3/cases.json --report pulse-advanced-report.json && python scripts/generate_reproduction_record.py pulse-advanced-report.json --output evidence/reproduction.json",
            "organization": "0xENX",
            "independentOfPrimeBeat": True,
        },
        "fixture": {
            "repositoryCommit": PULSE_COMMIT,
            "path": "fixtures/v0.3/cases.json",
            "sha256": PULSE_FIXTURE_SHA256,
            "caseCount": 80,
        },
        "environment": {
            "operatingSystem": platform.platform(),
            "architecture": platform.machine(),
            "dependencies": _dependencies(),
        },
        "results": _results(report),
        "notes": "Offline AP2 Payment Mandate to x402 exact/EIP-3009 boundary evaluation. This record does not claim settlement verification or protocol certification.",
        "publishedUrl": PUBLISHED_URL,
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(record, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(hashlib.sha256(args.output.read_bytes()).hexdigest())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
