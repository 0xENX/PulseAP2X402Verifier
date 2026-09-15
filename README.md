# Pulse AP2 to x402 Verifier

Built and maintained by **Enrico De Vito** ([@0xENX](https://github.com/0xENX)),
author of [TrustedPAI](https://trustedpai.com) — pre-execution risk screening for
agentic payments.

Linkedin contacts: (https://www.linkedin.com/in/lorenzodevito)

An independent offline evaluator for the AP2 Payment Mandate to x402 exact/EIP-3009 boundary in the pinned Pulse v0.3 corpus.

Written and maintained by [Enrico Lorenzo De Vito](https://github.com/0xENX), who also
builds [TrustedPAI](https://trustedpai.com) — pre-execution risk screening for
agent-initiated payments.

**The Pulse conformance corpus is not this project.** It belongs to
[shibutatsu](https://github.com/shibutatsu/pulse-ap2-x402-conformance); this evaluator
is an independent implementation that runs against it and claims nothing on its behalf.

## Independent acceptance

The maintainer of the Pulse corpus accepted this evaluator as **one of the two
qualifying implementations outside the original author** for their release-evidence
gate, and separately accepted the independent security review of their own verifier
published here as satisfying a second gate — after replaying the record with their
validator rather than taking the result on trust.

Both are interoperability and review evidence. Neither is a production audit, a
protocol certification, nor a release approval, and they are not presented as one.

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

Published. This section previously said the repository was a local preparation
workspace awaiting a disclosure review, which stopped being true when it was made
public and left the text contradicting the acceptance recorded above.

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE).

The Pulse AP2 to x402 conformance corpus is a separate work under its own
license and is not redistributed here; it is obtained at the pinned commit by
following the reproduction steps above.
