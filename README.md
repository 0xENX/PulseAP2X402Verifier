# Pulse AP2 to x402 Verifier

An independent offline evaluator for the AP2 Payment Mandate to x402 exact/EIP-3009 boundary in the pinned Pulse v0.3 corpus.

## Scope

The evaluator derives decisions and failure codes from the artifacts. It does not invoke a reference verifier and it does not read the fixture `expected` field.

It validates AP2 mandate and receipt evidence, AP2 to x402 bindings, EIP-712 / EIP-3009 signatures, and supplied settlement-evidence consistency. It does not claim on-chain settlement finality, token-balance verification, or protocol certification.

## Reproduce

Use Python 3.11 or later.

```bash
git clone https://github.com/shibutatsu/pulse-ap2-x402-conformance.git pulse-corpus
git -C pulse-corpus checkout --detach e06a6cbfe3ddb965c8fc70f50838f5014ec2038e
test "$(sha256sum pulse-corpus/fixtures/v0.3/cases.json | awk '{print $1}')" = "8f40be1bdc3d4458f758100e91b418b6a335c5d8d358723f118e2d3e1ad84ee0"

python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[test]'
python -m pytest -q
python -m pulse_ap2_x402_verifier.advanced pulse-corpus/fixtures/v0.3/cases.json --report pulse-advanced-report.json
python scripts/generate_reproduction_record.py pulse-advanced-report.json --output reproduction.json
cd pulse-corpus
npm ci
npx tsx src/evidence-cli.ts reproduction fixtures/v0.3/cases.json ../reproduction.json > ../official-reproduction-check.json
cd ..
python scripts/verify_official_reproduction.py official-reproduction-check.json
```

The final command exits with a nonzero status unless the official Pulse checker returns both `valid: true` and `automatedChecksPassed: true`. The generated record contains derived results only.

The GitHub Actions workflow runs the same official validation and publishes the evaluator report, formal reproduction record, record SHA-256, and official checker output as one artifact. A green workflow therefore requires a valid official reproduction record, not merely a completed evaluator process.

## Publication status

This repository is intended to be published only after an explicit disclosure review. Until then, it is a local preparation workspace and does not constitute a public qualification claim.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE).

The Pulse AP2 to x402 conformance corpus is a separate work under its own
license and is not redistributed here; it is obtained at the pinned commit by
following the reproduction steps above.
