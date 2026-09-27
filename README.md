# OpenIdentity Resolver

Reference resolver and immutable state-history service for **OpenIdentity Protocol v0.1.1**.

The resolver is a data-availability service, not a cryptographic authority. Clients must verify returned canonical state bytes and StateHash using an OpenIdentity SDK.

## First milestone

The initial service provides immutable state-history storage and two resolution endpoints:

```text
GET /v1/identities/{identity}
GET /v1/identities/{identity}/states/{stateHash}
```

For this bootstrap API, `identity` is the raw 32-byte IdentityId encoded as lowercase/uppercase hexadecimal and `stateHash` is the complete 34-byte SHA2-256 Multihash encoded as hexadecimal. A later interoperability layer will add `did:open:z...` and Multibase route forms without changing stored canonical data.

Responses include the canonical IdentityState bytes as unpadded base64url plus indexed metadata.

## Architecture

```text
HTTP resolution
      |
      v
PostgreSQL identity_state
      |
      +-- identity_id
      +-- sequence
      +-- state_hash
      +-- state_version
      +-- status
      +-- canonical_state_bytes  <- authoritative persisted representation
```

Metadata columns exist for indexing and query efficiency. `canonical_state_bytes` is the authoritative persisted protocol representation.

## Run locally

Requires Java 21, Maven, Docker and Docker Compose.

```bash
docker compose up -d
mvn spring-boot:run
```

Health:

```text
GET http://localhost:8080/actuator/health
```

## openidentity-java

Operation submission/validation will consume **openidentity-java 0.1.0** rather than reimplementing protocol transitions. Until the SDK artifacts are published to a Maven repository, install the SDK reactor locally:

```bash
cd ../openidentity-java
mvn clean install
```

The resolver consumes **openidentity-java 0.1.1** for canonical operation decoding and protocol transitions.

## Security model

Resolver responses are untrusted data until verified. A credential verifier should:

1. read `issuerIdentity` and `issuanceStateHash` from the signed native credential;
2. resolve that exact historical state;
3. canonicalize/hash the returned state and require equality with `issuanceStateHash`;
4. verify the credential against that historical state's AssertionPolicy.

This prevents resolver substitution from changing credential authority.


## Submit CREATE

`POST /v1/operations` currently accepts CREATE only.

The HTTP envelope uses unpadded base64url for canonical operation bytes, method IDs, and raw signatures:

```json
{
  "operation": "<base64url canonical CREATE bytes>",
  "proofs": [
    {
      "methodId": "<base64url 16-byte VerificationMethodId>",
      "signature": "<base64url raw signature>"
    }
  ]
}
```

The resolver decodes the operation through `OpenIdentityOperationDecoder`, verifies CREATE authorization with `CreateTransition`, derives canonical IdentityState bytes and StateHash, then atomically stores both the operation and resulting state.

Duplicate CREATE returns HTTP 409. Invalid operation/proof/authorization returns HTTP 400 with a stable error code.


## End-to-end V02 interoperability check

The repository pins the released Protocol v0.1.1 cryptographic-agility vector bundle for interoperability testing. Generate an HTTP request from normative vector V02:

```bash
python tools/v02-create-request.py > v02-request.txt
```

The first two lines show the expected identity and StateHash. The remainder is the JSON request body. A convenient Git Bash flow is:

```bash
python tools/v02-create-request.py
```

Copy only the printed JSON object into `v02.json`, then submit:

```bash
curl -i -X POST http://localhost:8080/v1/operations \
  -H "Content-Type: application/json" \
  --data-binary @v02.json
```

Expected result is HTTP 201. The returned `identity` must be:

```text
000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

and the returned `stateHash` must be:

```text
122091584ca3a54ebcf93d77c38ea09f68d33c99d6565c7aefab008bd11c09f5efa3
```

Resolve the persisted current state:

```bash
curl http://localhost:8080/v1/identities/000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
```

Then resolve the exact historical state:

```bash
curl http://localhost:8080/v1/identities/000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f/states/122091584ca3a54ebcf93d77c38ea09f68d33c99d6565c7aefab008bd11c09f5efa3
```

Submitting V02 a second time should return HTTP 409 `IDENTITY_ALREADY_EXISTS`.


## Local development wallet

For mutable lifecycle testing, use the local Ed25519 development wallet. The wallet contains private key material and is stored at `.openidentity/dev-wallet.json`; the entire `.openidentity/` directory is gitignored.

Initialize once:

```bash
mvn test-compile exec:java \
  -Dexec.classpathScope=test \
  -Dexec.mainClass=org.openidentity.resolver.tools.DevWalletCli \
  -Dexec.args=init
```

Generate a signed CREATE request from the wallet:

```bash
mvn test-compile exec:java \
  -Dexec.classpathScope=test \
  -Dexec.mainClass=org.openidentity.resolver.tools.DevWalletCli \
  -Dexec.args=create
```

The command prints the identity followed by a JSON request body. Save only the JSON object and submit it to `POST /v1/operations`.

The development wallet is for local interoperability testing only. Do not use it as production key-management infrastructure.
