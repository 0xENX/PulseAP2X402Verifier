"""Generate a publication-ready record from a completed offline evaluation."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _run_url() -> str:
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    repository = os.environ.get("GITHUB_REPOSITORY", "0xENX/PulseAP2X402Verifier")
    run_id = os.environ.get("GITHUB_RUN_ID", "not-recorded")
    return f"{server}/{repository}/actions/runs/{run_id}"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--pulse-commit", required=True)
    parser.add_argument("--fixture-sha256", required=True)
    args = parser.parse_args()

    report = json.loads(args.report.read_text(encoding="utf-8"))
    cases = report["cases"]
    consistent = report["consistent"]
    inconsistent = report["inconsistent"]
    if cases != 80 or consistent + inconsistent != cases:
        raise SystemExit("The report does not cover the complete 80-case corpus")

    verifier_commit = os.environ.get("GITHUB_SHA", "not-recorded")
    lines = [
        "# Pulse AP2 to x402 conformance record",
        "",
        "## Immutable execution reference",
        "",
        f"- Verifier repository commit: `{verifier_commit}`",
        f"- GitHub Actions run: {_run_url()}",
        "- Python runtime: `3.12` on `ubuntu-latest`",
        f"- Report SHA-256: `{_sha256(args.report)}`",
        "",
        "## Corpus identity",
        "",
        "- Source repository: `shibutatsu/pulse-ap2-x402-conformance`",
        f"- Pinned source commit: `{args.pulse_commit}`",
        "- Fixture: `fixtures/v0.3/cases.json`",
        f"- Fixture SHA-256: `{args.fixture_sha256}`",
        "",
        "## Derived evaluation record",
        "",
        f"- Cases evaluated: `{cases}`",
        f"- Consistent artifacts: `{consistent}`",
        f"- Inconsistent artifacts: `{inconsistent}`",
        "- The evaluator derives decisions and failure codes from supplied artifacts.",
        "- The evaluator does not invoke a reference verifier and does not read the fixture `expected` field.",
        "",
        "## Verification boundary",
        "",
        "Evaluated: AP2 mandate and receipt evidence, AP2 to x402 bindings, EIP-712 and EIP-3009 signatures, and supplied settlement-evidence consistency.",
        "",
        "Not claimed: on-chain settlement finality, token-balance verification, production protocol certification, or public Pulse qualification.",
        "",
        "The JSON report in the same workflow artifact contains each derived case result and failure-code set.",
    ]
    args.output.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
