# Independent security review — Pulse AP2 to x402 offline verifier

Reviewed commit `e06a6cbfe3ddb965c8fc70f50838f5014ec2038e`.

## Who did this and under what conditions

- Reviewer: Enrico De Vito
- Organization: TrustedPAI
- Public profile: https://github.com/0xENX
- Independent of Prime Beat: true
- Review date: 2026-09-05
- Environment: macOS 15.3.2 arm64, Node v22.23.2, npm 10.9.8, Python 3.12.6, uv 0.10.11
- Report URL: https://github.com/0xENX/PulseAP2X402Verifier/blob/9e08942d4214afc79808b0eb09fc8abcc127867e/docs/security-review/report.md
- Record URL: https://github.com/0xENX/PulseAP2X402Verifier/blob/9e08942d4214afc79808b0eb09fc8abcc127867e/docs/security-review/security-review.json

TrustedPAI is a commercial pre-execution screening service for agentic
payments. It has no commercial or contractual relationship with Prime Beat or
with Pulse. I also produced the qualifying 80-case reproduction in issue #16
of the Pulse repository. That is a separate artifact and a separate claim;
nothing in this review depends on it.

## The target, and how I fixed it

- Pulse commit `e06a6cbfe3ddb965c8fc70f50838f5014ec2038e`
- Fixture `fixtures/v0.3/cases.json`, SHA-256 `8f40be1b...84ee0`
- Evidence validator commit `fe24b304735c8ab1f38118a89d0a204bc7d00fe8`
- Review packet as pinned at `9940fdb`

I confirmed both before reading any code:

```
$ git -C pulse-review rev-parse HEAD
e06a6cbfe3ddb965c8fc70f50838f5014ec2038e
$ shasum -a 256 pulse-review/fixtures/v0.3/cases.json
8f40be1bdc3d4458f758100e91b418b6a335c5d8d358723f118e2d3e1ad84ee0
```

The checkout was never written to. I checked `git status --porcelain` after
every phase and it was empty each time.

## Method

I read the source and attacked it from a harness kept outside the frozen
checkout, in a directory that reads the pinned code and never writes to it.
Dependencies were installed at the versions the target's own lockfile pins.
Reviewing code against different library versions establishes nothing about
the code.

`docs/guarantee-boundary.md` was the work plan. Its left column is a list of
ten claims, and I treated each as something to falsify rather than confirm.
The question was never "is there a check here" but "is there an input that
makes this sentence false".

Every test starts from a case the verifier accepts, confirms it is still
accepted, and then changes one thing. Without that control a failure means
nothing — it may be the harness. That control caught two of my own mistakes,
one of which I would otherwise have written up as a finding.

One property of the target shapes everything. The case-level JCS/SHA-256
input hash covers the whole payload, so a naive mutation dies at
`INPUT_HASH_MISMATCH` before it reaches the thing being tested. Each mutation
recomputes that hash with the target's own `conformanceInputHash`.

My first run failed with `ReferenceError: crypto is not defined`. That was
Node 16 on my machine, not a defect: the project requires Node 22 or later
and its CI runs on 22 and 24. I redid everything on 22.23.2. Results from an
unsupported runtime would have been noise.

## Coverage

| Area | Status |
| --- | --- |
| Schemas, unsafe keys, unknown fields, source pins, JCS integrity, version separation | reviewed |
| 80-case corpus, negative tests, failure ordering, fail-closed prerequisites | reviewed |
| AP2 SD-JWT chain, key binding, disclosures, trust inputs, time, audience, nonce, receipt | reviewed |
| Signed constraints and AP2-to-x402 agreement | reviewed |
| x402 producer, accepted payload, settlement, unsupported extensions | reviewed |
| EIP-712 and EIP-3009 construction, low-s, recovery byte, payer recovery | reviewed |
| Evidence validators, confirmation policy, read-only public-EVM path | reviewed |
| Pinned AP2 artifact regeneration pipeline | reviewed |
| Locked dependencies, CI, mutation evidence, local-only behaviour | reviewed |

What follows is what actually happened in each of those.

## What held, and how hard I pushed

**Signature malleability.** This is where I expected to find something, and it
is where the code is strongest. For any valid ECDSA signature `(r, s, v)` the
pair `(r, n-s, v flipped)` is a different byte string that recovers the same
address. I built that variant from the fixture's own signature and the
verifier rejected it. Recovery bytes 0, 1, 26, 29 and 31 are rejected too;
only 27 and 28 pass. What matters more than the result is where the check
lives: `hasCanonicalSecp256k1S` runs before viem is called, so the protection
belongs to this project and does not depend on a library's current
behaviour. I recomputed `SECP256K1_HALF_ORDER` from the curve order and it
matches exactly. Eight adversarial cases plus a control.

**Cross-layer agreement.** The x402 requirements are not covered by the
EIP-712 signature, so if the agreement check were weak an attacker could
alter them while keeping a valid signature. I moved each unsigned field on
its own: payee, amount, asset, network, timeout, EIP-712 domain, settlement
payer and settlement network. Every one is caught, most by more than one
check. `maxTimeoutSeconds` is the interesting case: it is absent from the
signed message, so nothing but the agreement check stands behind it, and the
agreement check holds.

Then the attack that mattered. I moved every side at once — requirements, the
signed AP2 instrument, the EIP-3009 message and the accepted payload — so
that the layers agreed with each other. That fails with
`AP2_CLOSED_MANDATE_CLAIMS_HASH_MISMATCH`. The signed mandate is the anchor
and it cannot be moved. Sixteen adversarial cases plus a control.

**The AP2 chain.** Substituted root key, substituted receipt key, and the root
key reused as the receipt anchor are all rejected, so the two trust anchors
cannot be collapsed into one. A second delegation hop is rejected; so is
swapping root and leaf. A disclosure appended but referenced by no `_sd`
digest is rejected — the SD-JWT specification requires this and many
implementations skip it. I tried to widen the acceptance window by inflating
`clockSkewSeconds` and got `INPUT_SCHEMA_INVALID` instead: the schema caps it
at 300 seconds. Thirteen adversarial cases plus a control.

**Schemas and provenance.** Extra fields are rejected at the root, inside
requirements, inside the EIP-3009 authorization and inside the closed mandate.
`__proto__`, `constructor` and `prototype` are rejected at the root and
nested. The source pins are `z.literal()` values, different per fixture
generation, so a v0.1 pin cannot appear in a v0.3 case. Reordering keys is
accepted, which is correct: JCS canonicalises before hashing, and rejecting
it would have been the bug. Fourteen adversarial cases plus a control.

**The corpus.** All eighty cases run: eighty decisions and eighty ordered
failure-code lists match what the fixtures record, twenty accepts and sixty
rejects. This is the verifier agreeing with its own fixtures, not with an
outside oracle, and it should be read that way.

**Offline operation.** `SECURITY.md` states the verifier does not call RPC or
HTTP services. Rather than take that from the source, I replaced `fetch`,
`net.connect`, `Socket.prototype.connect`, `http.request`, `https.request`
and `dns.lookup` with traps that record and throw, then verified all eighty
cases. Eighty decisions agreed and nothing was recorded. `process.env`
appears once in the whole of `src/`, in the CLI, off the verification path.
The RPC client is constructed only in `evidence-cli.ts`; the library takes an
injected reader and opens nothing.

**The regeneration pipeline.** The shell script is careful: the uv version is
pinned and checked, the AP2 commit is pinned and verified with `rev-parse`
when the source is supplied, the checkout must be clean, installation uses
`--require-hashes`, and every `cd` is prefixed with `CDPATH=`. The Python
lockfile carries 367 hash lines from `uv pip compile --generate-hashes`.
Fixture keys are derived deterministically from public labels and marked as
fixture-only.

The one thing here I did not expect to have to check is hand-written
cryptography. `artifact_common.py` implements RFC 6979 deterministic nonce
derivation itself. A mistake there can repeat a nonce and leak the private
key, so reading it was not enough: I ran it against the official test vectors
in appendix A.2.5 for P-256 with SHA-256. It reproduces both exactly.

`verify_extract_artifacts.py` verifies rather than only extracting. It checks
the artifact version, the AP2 commit, the SHA-256 of the SDK's own
`mandate.py`, the exact case count, and calls the SDK's `MandateClient.verify`
with zero clock skew — stricter than the runtime verifier, which allows 300
seconds.

**Dependencies and CI.** Both ecosystems pin exact versions with no ranges.
Mutation testing covers the four security-relevant modules, breaks the build
below 70, excludes string-literal mutants on purpose and type-checks mutants
before running them. CI runs on Node 22 and 24, installs from the lockfile,
and regenerates the pinned AP2 artifacts twice, comparing the two runs
against each other and against expected hashes. CodeQL and dependency review
run separately.

## What I assumed, and what I did not look at

I assumed an attacker controls every JSON field, can send malformed
encodings and dangerous keys, can make layers disagree, can substitute keys
and signatures, can replay or expire authorizations, can lie in settlement
data and can forge evidence metadata. Supplied public JWKs, the stated
verification context, the pinned upstream sources and the local runtime are
trust inputs, not facts this repository authenticates.

Excluded because the packet excludes them: whether the trust anchors are
legitimate production anchors, whether any settlement happened or is final on
a live chain, whether a recovered address is an EOA or a smart account,
whether an authorization is still unused on-chain, and anything legal,
regulatory or operational.

Two limits that are mine rather than the packet's.

I never ran the pipeline on Linux. The preconditions for the first finding
below come from POSIX directory permissions and from reading the shell
parameter expansion, not from watching it happen on a Linux host.

The corpus agreement above is self-consistency. An independent oracle for the
same corpus exists — I wrote one — but that is a different artifact and it is
not evidence produced by this review.

## Findings

### TPAI-1 — medium — the pipeline runs an unvalidated interpreter from a predictable path

Status: open.

`scripts/ap2/run-pinned.sh` puts its cache at
`${AP2_PIPELINE_CACHE_DIR:-${TMPDIR:-/tmp}/pulse-ap2-${ap2_commit}}` and
creates the virtual environment only when `$venv_dir/bin/python` is not
already executable. If that file exists, the script uses it and runs both
pipeline stages through it. The path contains the AP2 commit, which is
written in the script, so it is entirely predictable. Where `TMPDIR` is unset
the fallback is `/tmp`, which anyone can create directories in.

Exploit conditions: a local user on a shared host who gets there before the
operator's first run. Not applicable on macOS, where the default `TMPDIR` is
per-user and mode 0700. Not applicable to this project's CI, which sets
`AP2_PIPELINE_CACHE_DIR` to the runner temporary directory.

Impact: code execution as the user running the pipeline, which is the user
signing the fixture artifacts.

I did not want to report this on reading alone. With a stubbed `uv` and a
planted executable, the unmodified script ran the plant for both stages; the
same run without the plant died at line 55, which attributes the difference
to the plant and nothing else. That still left one link open, because a
stubbed `uv` proves nothing about the real one. So I installed uv 0.10.11 and
wrote a binary that delegates to a real interpreter for uv's probes and
intercepts only the pipeline arguments. The script completed with exit status
0 and ran the impostor for both stages.

Recommendation: create the virtual environment somewhere the script owns, or
check that `$venv_dir/bin/python` came from this script before using it. The
same pattern appears more weakly on the AP2 source directory, where the
`rev-parse` check exists only on the `AP2_SOURCE_DIR` branch and the remote
URL of a pre-existing cache is never validated.

### TPAI-2 — low — the settlement is held to a weaker standard than the payload

Status: open.

Unknown extensions in `x402.payload.extensions` are rejected with
`X402_UNSUPPORTED_EXTENSION`, and an unknown key in `x402.requirements.extra`
is rejected by the schema. The settlement accepts arbitrary content in
`extensions` and `extra`, and accepts `success: true` alongside `errorReason`
or `errorMessage`. Neither field is read anywhere in the verifier.

This is not a bypass of anything cryptographic. The settlement is unsigned
and the boundary already says identifier equality proves nothing about the
chain. What it means is that unevaluated content, and a settlement that
contradicts itself, can sit inside a case the verifier calls consistent.

Recommendation: apply the same fail-closed check to `settlement.extensions`
and `settlement.extra`, and reject the error fields when `success` is true.

Eighteen adversarial cases plus a control across the payload, the settlement
and the accepted requirements.

### TPAI-3 — informational — the resource is unbound and the boundary reads as though it were not

Status: open.

The boundary says the "AP2 instrument extension, x402 requirement,
resource-bearing accepted payload, and EIP-3009 message agree". The verifier
never reads `x402.payload.resource`: url, description and mimeType can all
change and the case stays consistent.

The code is right. AP2 carries no equivalent field, so there is nothing to
agree with, and a verifier cannot check agreement against something that does
not exist. It is the document that reads wider than the exclusions state. A
later paragraph makes the intent clear — the payload must retain its resource
field — but it is twenty lines away and in another context.

Recommendation: one line in the right-hand column saying the resource is not
bound to the AP2 mandate.

### TPAI-4 — informational — the evidence RPC endpoint is not validated

Status: open.

`evidence-cli.ts` requires `PULSE_EVM_RPC_URL` to be non-empty and checks
nothing else, so a plaintext endpoint or a typo is used silently. The
operator sets the variable and this path sits outside the offline boundary,
which is why this is informational rather than low.

Recommendation: require https and validate the shape.

## Remediation and unresolved items

All four are open. None is critical or high, so the validator's automated
check is not held up by their status. TPAI-1 went through the repository's
private vulnerability reporting form before this document was published.

## Residual risk and conclusion

Bounded to commit `e06a6cbfe3ddb965c8fc70f50838f5014ec2038e`.

The offline decision boundary held against everything I built for it. The
controls that carry the weight are explicit and belong to this project rather
than to a library: low-s is enforced before viem is reached, the curve
constant is right, unreferenced disclosures are rejected, the two AP2 trust
anchors cannot be merged, and the signed mandate anchors the cross-layer
agreement well enough that moving every side at once still fails. Offline
operation is not merely claimed; I trapped the outbound primitives and
watched nothing happen.

None of the four findings is in that boundary. Three are about the surfaces
around it: an unsigned settlement held to a weaker standard than the signed
payload, a documented claim wider than the code, an unvalidated
operator-supplied endpoint. The fourth is in the regeneration pipeline and
needs a shared host and an unset `TMPDIR`.

This review does not establish production readiness, protocol conformance,
live settlement, custody assurance, or fitness for any deployment. It says
what held under the inputs described here, on the commit named above.

## Record and validator result

The machine-readable record is published beside this report as
`security-review.json`. I validated it from a checkout fixed at the evidence
validator commit, separate from the frozen review checkout:

```
$ git -C pulse-validator rev-parse HEAD
fe24b304735c8ab1f38118a89d0a204bc7d00fe8
$ npm --prefix pulse-validator run evidence:review -- .../security-review.json
{
  "valid": true,
  "automatedChecksPassed": true,
  "errors": []
}
$ echo $?
0
```

The validator checks the schema, the frozen commit, and whether a critical or
high finding is unresolved. It does not authenticate me, prove independence,
or judge how deep this review went.
