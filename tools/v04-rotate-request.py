#!/usr/bin/env python3
import base64, json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
vectors = json.loads(
    (root / "src/test/resources/openidentity-v0.1.1/cryptographic-agility-v0.1.json")
    .read_text(encoding="utf-8")
)
v = next(item for item in vectors["valid"] if item["id"] == "V04")

def b64url(hex_value):
    return base64.urlsafe_b64encode(bytes.fromhex(hex_value)).rstrip(b"=").decode("ascii")

request = {
    "operation": b64url(v["operationBytesHex"]),
    "proofs": [
        {
            "methodId": b64url(v["oldEd25519MethodIdHex"]),
            "signature": b64url(v["oldEd25519AuthorizationSignatureHex"]),
        },
        {
            "methodId": b64url(v["oldMlDsa65MethodIdHex"]),
            "signature": b64url(v["oldMlDsa65AuthorizationSignatureHex"]),
        },
    ],
    "proofsOfPossession": [
        {
            "methodId": b64url(v["newEd25519MethodIdHex"]),
            "signature": b64url(v["newEd25519PopSignatureHex"]),
        },
        {
            "methodId": b64url(v["newMlDsa65MethodIdHex"]),
            "signature": b64url(v["newMlDsa65PopSignatureHex"]),
        },
    ],
}

print("Identity:", v["identityHex"])
print("Previous StateHash:", v["previousStateHashHex"])
print("Expected Resulting StateHash:", v["resultingStateHashHex"])
print(json.dumps(request, indent=2))
