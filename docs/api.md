# OpenIdentity Resolver HTTP API

Version 0.1.0 implements resolution and operation submission for OpenIdentity Protocol v0.1.1.

## Trust model

Resolver responses are data, not authority. A consumer that relies on a resolved historical state MUST decode its canonical bytes and recompute its StateHash. Credential verification MUST use the exact state identified by the credential's signed `issuanceStateHash`, not the current identity state.

## Encoding

Route `identity` values are 32-byte IdentityIds encoded as hexadecimal. Route `stateHash` values are complete 34-byte SHA2-256 Multihashes encoded as hexadecimal.

Operation submission uses unpadded base64url for canonical operation bytes, 16-byte VerificationMethodIds, and raw signatures. Resolved `canonicalState` is unpadded base64url deterministic CBOR.

## Resolve current state

```http
GET /v1/identities/{identity}
```

Returns HTTP 200 with:

```json
{
  "identity": "<hex>",
  "sequence": 4,
  "stateHash": "<hex multihash>",
  "stateVersion": 2,
  "status": 1,
  "canonicalState": "<base64url CBOR>",
  "createdAt": "<timestamp>"
}
```

Returns 404 when the identity has no state history and 400 for malformed identifiers.

## Resolve historical state

```http
GET /v1/identities/{identity}/states/{stateHash}
```

Returns the exact immutable state for the identity/hash pair. This endpoint is the resolver primitive used by OI-003 historical credential verification.

## Submit operation

```http
POST /v1/operations
Content-Type: application/json
```

```json
{
  "operation": "<base64url canonical operation bytes>",
  "proofs": [
    {
      "methodId": "<base64url VerificationMethodId>",
      "signature": "<base64url raw signature>"
    }
  ],
  "proofsOfPossession": []
}
```

The meaning of the proof collections depends on operation type:

| Operation | `proofs` | `proofsOfPossession` |
| --- | --- | --- |
| CREATE | proposed ControllerPolicy authorization | unused |
| ROTATE_CONTROLLER | current ControllerPolicy authorization | proposed controller PoP |
| SET_ASSERTION_POLICY | current ControllerPolicy authorization | proposed assertion-authority PoP; empty when removing authority |
| DEACTIVATE | current ControllerPolicy authorization | unused |
| RECOVER | revealed RecoveryPolicy authorization | new controller PoP |

Successful operations return HTTP 201 and the resulting state metadata:

```json
{
  "identity": "<hex>",
  "sequence": 2,
  "stateHash": "<hex multihash>",
  "stateVersion": 1,
  "status": 1
}
```

The resolver delegates canonical decoding, transition validation, signature verification, policy thresholds, predecessor checks, proof-of-possession, and recovery rules to `openidentity-java`.

## Errors

Errors are JSON objects with `status`, `error`, `message`, and `timestamp`. Malformed or unauthorized protocol submissions return 400. Duplicate CREATE returns 409 `IDENTITY_ALREADY_EXISTS`; conflicting later writes return 409 `OPERATION_CONFLICT`. Resolution of absent state returns 404.

## Health

```http
GET /actuator/health
```

Liveness and readiness probes are enabled.
