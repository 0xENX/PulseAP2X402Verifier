"""Assess AP2 to x402 fixture consistency without using a reference verifier."""

import argparse
import base64
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any


PINNED_FIXTURE_SHA256 = "8f40be1bdc3d4458f758100e91b418b6a335c5d8d358723f118e2d3e1ad84ee0"
SUPPORTED_BUNDLE_VERSION = "ap2-x402-conformance-bundle/0.3"
ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
BYTES32 = re.compile(r"^0x[0-9a-fA-F]{64}$")
X402_EXTENSION_FIELDS = frozenset({
    "version",
    "scheme",
    "network",
    "asset",
    "amount",
    "payTo",
    "payer",
    "ap2PayeeId",
    "ap2PaymentAmount",
    "maxTimeoutSeconds",
    "eip712Domain",
    "nonceBinding",
})


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _same(left: Any, right: Any) -> bool:
    if isinstance(left, str) and isinstance(right, str) and left.startswith("0x") and right.startswith("0x"):
        return left.lower() == right.lower()
    return left == right


def _add_if_different(issues: list[str], code: str, left: Any, right: Any) -> None:
    if not _same(left, right):
        issues.append(code)


def _constraint(open_mandate: dict[str, Any], kind: str) -> dict[str, Any]:
    constraints = open_mandate.get("constraints")
    if not isinstance(constraints, list):
        return {}
    for item in constraints:
        if isinstance(item, dict) and item.get("type") == kind:
            return item
    return {}


def _decode_reference_nonce(reference: Any) -> str | None:
    if not isinstance(reference, str):
        return None
    try:
        padded = reference + "=" * (-len(reference) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (UnicodeEncodeError, ValueError):
        return None
    if len(decoded) != 32:
        return None
    return "0x" + decoded.hex()


def evaluate_case(case: dict[str, Any]) -> dict[str, Any]:
    """Evaluate only TrustedPAI-owned structural binding rules.

    The fixture's expected decision is intentionally ignored. This function
    does not verify SD-JWT signatures, receipt signatures, EIP-712 signatures,
    issuer trust, or on-chain settlement.
    """
    ap2 = _as_dict(case.get("ap2"))
    x402 = _as_dict(case.get("x402"))
    closed = _as_dict(ap2.get("closedMandate"))
    opened = _as_dict(ap2.get("openMandate"))
    receipt = _as_dict(ap2.get("paymentReceipt"))
    verification = _as_dict(ap2.get("verification"))
    requirements = _as_dict(x402.get("requirements"))
    payload = _as_dict(x402.get("payload"))
    accepted = _as_dict(payload.get("accepted"))
    authorization = _as_dict(_as_dict(payload.get("payload")).get("authorization"))
    settlement = _as_dict(x402.get("settlement"))
    instrument = _as_dict(closed.get("payment_instrument"))
    instrument_x402 = _as_dict(instrument.get("x402"))
    payment_amount = _as_dict(closed.get("payment_amount"))
    payee = _as_dict(closed.get("payee"))
    issues: list[str] = []

    if not ap2 or not x402 or not closed or not opened or not requirements or not payload:
        issues.append("INPUT_SCHEMA_INVALID")
        return _result(case, issues)

    _add_if_different(
        issues,
        "AP2_CLOSED_TRANSACTION_ID_MISMATCH",
        closed.get("transaction_id"),
        verification.get("openCheckoutReference"),
    )
    if instrument.get("type") != "x402" or not instrument_x402:
        issues.append("AP2_PAYMENT_INSTRUMENT_NOT_ALLOWED")
        return _result(case, issues)
    unknown_instrument_fields = set(instrument_x402).difference(X402_EXTENSION_FIELDS)
    if unknown_instrument_fields:
        issues.append("AP2_X402_UNSUPPORTED_EXTENSION")

    reference_constraint = _constraint(opened, "payment.reference")
    if _same(closed.get("transaction_id"), verification.get("openCheckoutReference")):
        _add_if_different(
            issues,
            "AP2_PAYMENT_REFERENCE_MISMATCH",
            closed.get("transaction_id"),
            reference_constraint.get("conditional_transaction_id"),
        )
    allowed_instruments = _constraint(opened, "payment.allowed_payment_instruments").get("allowed")
    allowed_instrument = next(
        (item for item in allowed_instruments or [] if isinstance(item, dict) and item.get("id") == instrument.get("id")),
        {},
    )
    if not allowed_instrument or allowed_instrument.get("type") != "x402" or not _as_dict(allowed_instrument.get("x402")):
        issues.append("AP2_PAYMENT_INSTRUMENT_NOT_ALLOWED")
    allowed_payees = _constraint(opened, "payment.allowed_payees").get("allowed")
    if not any(isinstance(item, dict) and item.get("id") == payee.get("id") for item in allowed_payees or []):
        issues.append("AP2_PAYEE_NOT_ALLOWED")
    amount_range = _constraint(opened, "payment.amount_range")
    if not (
        _same(amount_range.get("currency"), payment_amount.get("currency"))
        and isinstance(amount_range.get("min"), int)
        and isinstance(amount_range.get("max"), int)
        and isinstance(payment_amount.get("amount"), int)
        and amount_range["min"] <= payment_amount["amount"] <= amount_range["max"]
    ):
        issues.append("AP2_AMOUNT_CONSTRAINT_MISMATCH")

    bindings = {
        "scheme": (instrument_x402.get("scheme"), requirements.get("scheme")),
        "network": (instrument_x402.get("network"), requirements.get("network")),
        "asset": (instrument_x402.get("asset"), requirements.get("asset")),
        "amount": (instrument_x402.get("amount"), requirements.get("amount")),
        "payTo": (instrument_x402.get("payTo"), requirements.get("payTo")),
        "maxTimeoutSeconds": (instrument_x402.get("maxTimeoutSeconds"), requirements.get("maxTimeoutSeconds")),
    }
    for field, (left, right) in bindings.items():
        if field == "payTo":
            _add_if_different(issues, "AP2_X402_COMMERCE_BINDING_MISMATCH", left, right)
        elif field == "maxTimeoutSeconds":
            _add_if_different(issues, "AP2_X402_TIMEOUT_MISMATCH", left, right)
            if not _same(left, right):
                issues.append("AP2_UNSUPPORTED_CONSTRAINT")
        else:
            _add_if_different(issues, f"AP2_X402_{field.upper()}_MISMATCH", left, right)
    _add_if_different(issues, "AP2_X402_PAYEE_MISMATCH", instrument_x402.get("ap2PayeeId"), payee.get("id"))
    _add_if_different(issues, "AP2_X402_COMMERCE_BINDING_MISMATCH", instrument_x402.get("ap2PaymentAmount"), payment_amount)
    _add_if_different(
        issues,
        "AP2_X402_EIP712_DOMAIN_MISMATCH",
        instrument_x402.get("eip712Domain"),
        {"name": _as_dict(requirements.get("extra")).get("name"), "version": _as_dict(requirements.get("extra")).get("version")},
    )

    for field in ("scheme", "network", "asset", "amount", "payTo", "maxTimeoutSeconds"):
        _add_if_different(issues, "X402_ACCEPTED_REQUIREMENTS_MISMATCH", requirements.get(field), accepted.get(field))
    _add_if_different(issues, "X402_ACCEPTED_REQUIREMENTS_MISMATCH", requirements.get("extra"), accepted.get("extra"))
    if not _same(requirements.get("scheme"), accepted.get("scheme")):
        issues.append("X402_UNSUPPORTED_EXTENSION")

    reference = verification.get("closedMandateReference")
    requirement_extra = _as_dict(requirements.get("extra"))
    _add_if_different(issues, "X402_MANDATE_REFERENCE_MISMATCH", reference, requirement_extra.get("ap2MandateReference"))
    expected_nonce = _decode_reference_nonce(reference)
    if expected_nonce is None or not _same(expected_nonce, authorization.get("nonce")):
        issues.append("EIP3009_NONCE_BINDING_MISMATCH")
    _add_if_different(issues, "EIP3009_PAYER_MISMATCH", instrument_x402.get("payer"), authorization.get("from"))
    _add_if_different(issues, "EIP3009_RECIPIENT_MISMATCH", requirements.get("payTo"), authorization.get("to"))
    _add_if_different(issues, "EIP3009_VALUE_MISMATCH", requirements.get("amount"), authorization.get("value"))
    now = case.get("nowEpochSeconds")
    valid_after = _integer(authorization.get("validAfter"))
    valid_before = _integer(authorization.get("validBefore"))
    timeout = _integer(requirements.get("maxTimeoutSeconds"))
    expiry = _integer(closed.get("exp"))
    if not isinstance(now, int) or valid_after is None or valid_before is None or timeout is None or expiry is None:
        issues.append("INPUT_SCHEMA_INVALID")
    else:
        if valid_after > now:
            issues.append("EIP3009_VALID_AFTER_IN_FUTURE")
        if valid_before < now + 6:
            issues.append("EIP3009_VALID_BEFORE_EXPIRED")
        if valid_before > now + timeout:
            issues.append("EIP3009_VALIDITY_EXCEEDS_TIMEOUT")
        if valid_before > expiry:
            issues.append("EIP3009_VALIDITY_EXCEEDS_AP2_EXPIRY")

    if settlement.get("success") is not True:
        issues.append("SETTLEMENT_FAILED")
    _add_if_different(issues, "SETTLEMENT_NETWORK_MISMATCH", requirements.get("network"), settlement.get("network"))
    _add_if_different(issues, "SETTLEMENT_PAYER_MISMATCH", authorization.get("from"), settlement.get("payer"))
    if not isinstance(settlement.get("transaction"), str) or not BYTES32.fullmatch(settlement["transaction"]):
        issues.append("SETTLEMENT_TRANSACTION_INVALID")
    if "amount" in settlement:
        _add_if_different(issues, "SETTLEMENT_AMOUNT_MISMATCH", requirements.get("amount"), settlement.get("amount"))
    if receipt.get("status") == "Success":
        _add_if_different(issues, "AP2_RECEIPT_TRANSACTION_MISMATCH", receipt.get("network_confirmation_id"), settlement.get("transaction"))
    if receipt.get("status") != "Success":
        issues.append("AP2_RECEIPT_NOT_SUCCESSFUL")
    _add_if_different(issues, "AP2_RECEIPT_REFERENCE_MISMATCH", reference, receipt.get("reference"))
    if not all(isinstance(value, str) and ADDRESS.fullmatch(value) for value in (requirements.get("asset"), requirements.get("payTo"), authorization.get("from"), authorization.get("to"))):
        issues.append("EVM_ADDRESS_INVALID")
    return _result(case, issues)


def _integer(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _result(case: dict[str, Any], issues: list[str]) -> dict[str, Any]:
    unique_issues = list(dict.fromkeys(issues))
    return {
        "case_id": case.get("id"),
        "structurally_consistent": not unique_issues,
        "failure_codes": unique_issues,
        "verification_scope": {
            "structural_binding": "evaluated",
            "ap2_sd_jwt_signatures": "not_evaluated",
            "ap2_receipt_signature": "not_evaluated",
            "eip712_signature": "not_evaluated",
            "on_chain_settlement": "not_evaluated",
        },
    }


def load_bundle(path: Path, required_sha256: str) -> list[dict[str, Any]]:
    actual_sha256 = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual_sha256 != required_sha256:
        raise ValueError(f"Fixture SHA-256 mismatch: expected {required_sha256}, received {actual_sha256}")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("bundleVersion") != SUPPORTED_BUNDLE_VERSION:
        raise ValueError(f"Unsupported fixture bundle version: {data.get('bundleVersion')!r}")
    cases = data.get("cases")
    if not isinstance(cases, list) or len(cases) != 80:
        raise ValueError("Fixture bundle must contain exactly 80 cases")
    return [_remove_non_evaluation_fields(case) for case in cases if isinstance(case, dict)]


def _remove_non_evaluation_fields(value: Any) -> Any:
    if isinstance(value, list):
        return [_remove_non_evaluation_fields(item) for item in value]
    if not isinstance(value, dict):
        return value
    return {
        key: _remove_non_evaluation_fields(item)
        for key, item in value.items()
        if key != "expected"
    }


def run(path: Path, required_sha256: str = PINNED_FIXTURE_SHA256) -> dict[str, Any]:
    cases = load_bundle(path, required_sha256)
    results = [evaluate_case(case) for case in cases]
    failures = Counter(code for result in results for code in result["failure_codes"])
    return {
        "fixture_path": str(path),
        "fixture_sha256": required_sha256,
        "cases": len(results),
        "structurally_consistent": sum(result["structurally_consistent"] for result in results),
        "structurally_inconsistent": sum(not result["structurally_consistent"] for result in results),
        "verification_boundary": "offline structural AP2/x402 binding only",
        "not_claimed": [
            "AP2 SD-JWT cryptographic verification",
            "AP2 receipt cryptographic verification",
            "EIP-712 signature verification",
            "on-chain settlement or finality verification",
            "Pulse conformance qualification",
        ],
        "failure_code_counts": dict(sorted(failures.items())),
        "results": results,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path, help="Local path to the pinned Pulse v0.3 fixture bundle")
    parser.add_argument("--sha256", default=PINNED_FIXTURE_SHA256, help="Required fixture SHA-256")
    parser.add_argument("--report", type=Path, help="Optional JSON report path")
    args = parser.parse_args()
    try:
        report = run(args.fixture, args.sha256)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        parser.error(str(exc))
    serialized = json.dumps(report, indent=2, sort_keys=True)
    print(serialized)
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(serialized + "\n", encoding="utf-8")
        print(f"Report written to {args.report}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
