#!/usr/bin/env python3
import base64, json
from pathlib import Path

root = Path(__file__).resolve().parents[1]
vector_file = root / "src/test/resources/openidentity-v0.1.1/cryptographic-agility-v0.1.json"
vectors = json.loads(vector_file.read_text(encoding="utf-8"))
v = next(item for item in vectors["valid"] if item["id"] == "V02")

def b64url(hex_value):
    return base64.urlsafe_b64encode(bytes.fromhex(hex_value)).rstrip(b"=").decode("ascii")

request = {
    "operation": b64url(v["operationBytesHex"]),
    "proofs": [
        {"methodId": b64url(v["ed25519MethodIdHex"]), "signature": b64url(v["ed25519SignatureHex"])},
        {"methodId": b64url(v["mlDsa65MethodIdHex"]), "signature": b64url(v["mlDsa65SignatureHex"])},
    ],
}
print("Identity:", v["identityHex"])
print("Expected StateHash:", v["stateHashHex"])
print(json.dumps(request, indent=2))
