"""Independently assess the pinned AP2 to x402 conformance bundle offline."""

import argparse
import base64
import hashlib
import json
import re
from collections import Counter
from pathlib import Path
from typing import Any

from eth_account import Account
from eth_account.messages import encode_typed_data
from jwcrypto import jwk as jwcrypto_jwk

from .preflight import PINNED_FIXTURE_SHA256, evaluate_case, load_bundle


ADDRESS = re.compile(r"^0x[0-9a-fA-F]{40}$")
SIGNATURE = re.compile(r"^0x[0-9a-fA-F]{130}$")
SECP256K1_HALF_ORDER = 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0


def _b64url_sha256(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _canonical_claims_hash(value: Any) -> str:
    serialized = json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    return _b64url_sha256(serialized)


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _jwt_payload(token: str) -> dict[str, Any]:
    try:
        encoded = token.split(".")[1]
        encoded += "=" * (-len(encoded) % 4)
        value = json.loads(base64.urlsafe_b64decode(encoded))
    except (IndexError, UnicodeDecodeError, ValueError):
        return {}
    return _as_dict(value)


def _chain_id(network: Any) -> int | None:
    if not isinstance(network, str) or not network.startswith("eip155:"):
        return None
    try:
        value = int(network.split(":", 1)[1])
    except ValueError:
        return None
    return value if value > 0 else None


def _canonical_eip3009_signature(signature: Any) -> bool:
    if not isinstance(signature, str) or not SIGNATURE.fullmatch(signature):
        return False
    s_value = int(signature[66:130], 16)
    return 0 < s_value <= SECP256K1_HALF_ORDER and int(signature[130:132], 16) in {27, 28}


def _eip3009_typed_data(requirements: dict[str, Any], authorization: dict[str, Any]) -> dict[str, Any] | None:
    extra = _as_dict(requirements.get("extra"))
    chain_id = _chain_id(requirements.get("network"))
    required_values = (
        requirements.get("asset"),
        extra.get("name"),
        extra.get("version"),
        authorization.get("from"),
        authorization.get("to"),
        authorization.get("value"),
        authorization.get("validAfter"),
        authorization.get("validBefore"),
        authorization.get("nonce"),
    )
    if chain_id is None or not all(isinstance(value, str) and value for value in required_values):
        return None
    if not all(ADDRESS.fullmatch(value) for value in (requirements["asset"], authorization["from"], authorization["to"])):
        return None
    return {
        "types": {
            "EIP712Domain": [
                {"name": "name", "type": "string"},
                {"name": "version", "type": "string"},
                {"name": "chainId", "type": "uint256"},
                {"name": "verifyingContract", "type": "address"},
            ],
            "TransferWithAuthorization": [
                {"name": "from", "type": "address"},
                {"name": "to", "type": "address"},
                {"name": "value", "type": "uint256"},
                {"name": "validAfter", "type": "uint256"},
                {"name": "validBefore", "type": "uint256"},
                {"name": "nonce", "type": "bytes32"},
            ],
        },
        "primaryType": "TransferWithAuthorization",
        "domain": {
            "name": extra["name"],
            "version": extra["version"],
            "chainId": chain_id,
            "verifyingContract": requirements["asset"],
        },
        "message": {
            "from": authorization["from"],
            "to": authorization["to"],
            "value": int(authorization["value"]),
            "validAfter": int(authorization["validAfter"]),
            "validBefore": int(authorization["validBefore"]),
            "nonce": authorization["nonce"],
        },
    }


def _verify_eip3009(case: dict[str, Any]) -> list[str]:
    x402 = _as_dict(case.get("x402"))
    requirements = _as_dict(x402.get("requirements"))
    payload = _as_dict(x402.get("payload"))
    inner = _as_dict(payload.get("payload"))
    authorization = _as_dict(inner.get("authorization"))
    signature = inner.get("signature")
    typed_data = _eip3009_typed_data(requirements, authorization)
    if typed_data is None:
        return ["EIP3009_TYPED_DATA_INVALID"]
    if not _canonical_eip3009_signature(signature):
        return ["EIP3009_SIGNATURE_INVALID"]
    try:
        signer = Account.recover_message(encode_typed_data(full_message=typed_data), signature=signature)
    except (TypeError, ValueError):
        return ["EIP3009_SIGNATURE_INVALID"]
    if signer.lower() != authorization["from"].lower():
        return ["EIP3009_SIGNER_MISMATCH"]
    return []


def _verify_ap2(case: dict[str, Any]) -> list[str]:
    try:
        from ap2.sdk.mandate import MandateClient
        from ap2.sdk.receipt_wrapper import ReceiptClient
    except ImportError as exc:
        raise RuntimeError("AP2 SDK is required for advanced conformance verification") from exc

    ap2 = _as_dict(case.get("ap2"))
    verification = _as_dict(ap2.get("verification"))
    evidence = _as_dict(verification.get("cryptographicEvidence"))
    trusted_root = _as_dict(evidence.get("trustedRootPublicJwk"))
    trusted_receipt = _as_dict(evidence.get("trustedReceiptPublicJwk"))
    mandate_chain = evidence.get("mandateChain")
    receipt_jwt = evidence.get("paymentReceiptJwt")
    audience = evidence.get("expectedAudience")
    nonce = evidence.get("expectedNonce")
    now = verification.get("verifiedAtEpochSeconds")
    skew = verification.get("clockSkewSeconds")
    failures: list[str] = []
    if _canonical_claims_hash(ap2.get("openMandate")) != verification.get("openMandateClaimsHash"):
        failures.append("AP2_OPEN_MANDATE_CLAIMS_HASH_MISMATCH")
    if _canonical_claims_hash(ap2.get("closedMandate")) != verification.get("closedMandateClaimsHash"):
        failures.append("AP2_CLOSED_MANDATE_CLAIMS_HASH_MISMATCH")
    if not all(isinstance(value, str) and value for value in (mandate_chain, receipt_jwt, audience, nonce)):
        return failures + ["AP2_CRYPTOGRAPHIC_EVIDENCE_INVALID"]
    if not isinstance(now, int) or not isinstance(skew, int):
        return failures + ["AP2_CRYPTOGRAPHIC_EVIDENCE_INVALID"]
    try:
        root_key = jwcrypto_jwk.JWK.from_json(json.dumps(trusted_root))
        mandate_client = MandateClient()
        effective_claims = mandate_client.verify(
            mandate_chain,
            lambda _token: root_key,
            expected_aud=audience,
            expected_nonce=nonce,
            clock_skew_seconds=skew,
            current_time=now,
        )
    except Exception as exc:
        message = str(exc).lower()
        if "nonce" in message or "aud" in message or "key binding" in message:
            return failures + ["AP2_KEY_BINDING_UNVERIFIED"]
        return failures + ["AP2_OPEN_MANDATE_UNVERIFIED"]

    if not isinstance(effective_claims, list) or len(effective_claims) < 2:
        return failures + ["AP2_CRYPTOGRAPHIC_EVIDENCE_INVALID"]
    if effective_claims[0] != ap2.get("openMandate"):
        failures.append("AP2_OPEN_MANDATE_CLAIMS_HASH_MISMATCH")
    if effective_claims[-1] != ap2.get("closedMandate"):
        failures.append("AP2_CLOSED_MANDATE_CLAIMS_HASH_MISMATCH")
    try:
        closed_mandate = MandateClient().get_closed_mandate_jwt(mandate_chain)
        expected_reference = _b64url_sha256(closed_mandate)
        receipt_key = jwcrypto_jwk.JWK.from_json(json.dumps(trusted_receipt))
        result = ReceiptClient().verify_receipt(
            receipt_jwt=receipt_jwt,
            receipt_issuer_public_key=receipt_key,
            has_reference_in_store_cb=lambda reference: reference == expected_reference,
            is_payment_receipt=True,
        )
    except Exception:
        return failures + ["AP2_RECEIPT_UNVERIFIED"]
    if result.get("verified") is not True:
        return failures + ["AP2_RECEIPT_UNVERIFIED"]
    receipt_claims = _jwt_payload(receipt_jwt)
    if not receipt_claims or receipt_claims != _as_dict(ap2.get("paymentReceipt")):
        failures.append("AP2_RECEIPT_UNVERIFIED")
    if receipt_claims.get("status") != _as_dict(ap2.get("paymentReceipt")).get("status"):
        failures.append("AP2_OPEN_PRESET_MISMATCH")
    return failures


def _verify_all_allowed_instruments(case: dict[str, Any]) -> list[str]:
    ap2 = _as_dict(case.get("ap2"))
    open_mandate = _as_dict(ap2.get("openMandate"))
    closed = _as_dict(ap2.get("closedMandate"))
    closed_instrument = _as_dict(closed.get("payment_instrument"))
    constraints = open_mandate.get("constraints")
    if not isinstance(constraints, list):
        return ["AP2_PAYMENT_INSTRUMENT_NOT_ALLOWED"]
    matching_constraints = [
        item for item in constraints
        if isinstance(item, dict) and item.get("type") == "payment.allowed_payment_instruments"
    ]
    if not matching_constraints:
        return ["AP2_PAYMENT_INSTRUMENT_NOT_ALLOWED"]
    for constraint in matching_constraints:
        allowed = constraint.get("allowed")
        if not isinstance(allowed, list) or not any(
            isinstance(candidate, dict) and candidate == closed_instrument for candidate in allowed
        ):
            return ["AP2_CONSTRAINT_VIOLATION", "AP2_PAYMENT_INSTRUMENT_NOT_ALLOWED"]
    return []


def _x402_schema_is_valid(case: dict[str, Any]) -> bool:
    closed = _as_dict(_as_dict(case.get("ap2")).get("closedMandate"))
    instrument = _as_dict(closed.get("payment_instrument"))
    if instrument.get("type") != "x402":
        return True
    extension = instrument.get("x402")
    if not isinstance(extension, dict):
        return False
    required = {
        "version", "scheme", "network", "asset", "amount", "payTo", "payer",
        "ap2PayeeId", "ap2PaymentAmount", "maxTimeoutSeconds", "eip712Domain", "nonceBinding",
    }
    return required.issubset(extension) and set(extension).issubset(required)


def evaluate_advanced_case(case: dict[str, Any]) -> dict[str, Any]:
    if not _x402_schema_is_valid(case):
        return {
            "case_id": case.get("id"),
            "consistent": False,
            "failure_codes": ["INPUT_SCHEMA_INVALID"],
            "verification_scope": {"structural_binding": "not_evaluated", "on_chain_settlement": "not_evaluated"},
        }
    structural = evaluate_case(case)
    failure_codes = list(structural["failure_codes"])
    failure_codes.extend(_verify_ap2(case))
    failure_codes.extend(_verify_all_allowed_instruments(case))
    failure_codes.extend(_verify_eip3009(case))
    failure_codes = list(dict.fromkeys(failure_codes))
    return {
        "case_id": case.get("id"),
        "consistent": not failure_codes,
        "failure_codes": failure_codes,
        "verification_scope": {
            "structural_binding": "evaluated",
            "ap2_mandate_signatures_and_key_binding": "evaluated",
            "ap2_receipt_signature": "evaluated",
            "eip712_eip3009_signature": "evaluated",
            "on_chain_settlement": "not_evaluated",
        },
    }


def run(path: Path, required_sha256: str = PINNED_FIXTURE_SHA256) -> dict[str, Any]:
    cases = load_bundle(path, required_sha256)
    results = [evaluate_advanced_case(case) for case in cases]
    failure_counts = Counter(code for result in results for code in result["failure_codes"])
    return {
        "fixture_path": str(path),
        "fixture_sha256": required_sha256,
        "cases": len(results),
        "consistent": sum(result["consistent"] for result in results),
        "inconsistent": sum(not result["consistent"] for result in results),
        "verification_boundary": "offline AP2 mandate and receipt cryptography, AP2/x402 binding, and EIP-3009 signature verification",
        "not_claimed": [
            "on-chain settlement or token balance verification",
            "public Pulse conformance qualification",
            "production protocol certification",
        ],
        "failure_code_counts": dict(sorted(failure_counts.items())),
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
    except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as exc:
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
