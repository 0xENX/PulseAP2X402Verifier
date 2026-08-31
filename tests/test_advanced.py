from eth_account import Account
from eth_account.messages import encode_typed_data
from pulse_ap2_x402_verifier import advanced as MODULE



def _requirements() -> dict:
    return {
        "network": "eip155:84532",
        "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
        "extra": {"name": "USDC", "version": "2"},
    }


def _authorization(account) -> dict:
    return {
        "from": account.address,
        "to": "0x0000000000000000000000000000000001",
        "value": "100",
        "validAfter": "1000",
        "validBefore": "1100",
        "nonce": "0x" + "11" * 32,
    }


def test_eip3009_verification_accepts_a_real_canonical_signature():
    account = Account.create()
    requirements = _requirements()
    authorization = _authorization(account)
    authorization["to"] = account.address
    typed_data = MODULE._eip3009_typed_data(requirements, authorization)
    assert typed_data is not None
    signature = Account.sign_message(encode_typed_data(full_message=typed_data), account.key).signature.hex()
    case = {"x402": {"requirements": requirements, "payload": {"payload": {"authorization": authorization, "signature": "0x" + signature}}}}

    assert MODULE._verify_eip3009(case) == []


def test_eip3009_verification_rejects_a_tampered_signed_value():
    account = Account.create()
    requirements = _requirements()
    authorization = _authorization(account)
    authorization["to"] = account.address
    typed_data = MODULE._eip3009_typed_data(requirements, authorization)
    assert typed_data is not None
    signature = Account.sign_message(encode_typed_data(full_message=typed_data), account.key).signature.hex()
    authorization["value"] = "101"
    case = {"x402": {"requirements": requirements, "payload": {"payload": {"authorization": authorization, "signature": "0x" + signature}}}}

    assert MODULE._verify_eip3009(case) == ["EIP3009_SIGNER_MISMATCH"]


def test_x402_extension_schema_rejects_missing_required_binding():
    case = {
        "ap2": {
            "closedMandate": {
                "payment_instrument": {
                    "type": "x402",
                    "x402": {"scheme": "exact"},
                }
            }
        }
    }

    result = MODULE.evaluate_advanced_case(case)

    assert result["consistent"] is False
    assert result["failure_codes"] == ["INPUT_SCHEMA_INVALID"]


def test_x402_extension_schema_accepts_complete_binding_shape():
    case = {
        "ap2": {
            "closedMandate": {
                "payment_instrument": {
                    "type": "x402",
                    "x402": {
                        "version": 2,
                        "scheme": "exact",
                        "network": "eip155:84532",
                        "asset": "asset",
                        "amount": "100",
                        "payTo": "merchant",
                        "payer": "payer",
                        "ap2PayeeId": "merchant",
                        "ap2PaymentAmount": "100",
                        "maxTimeoutSeconds": 60,
                        "eip712Domain": {},
                        "nonceBinding": "nonce",
                    },
                }
            }
        }
    }

    assert MODULE._x402_schema_is_valid(case) is True
