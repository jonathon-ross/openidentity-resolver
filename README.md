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

The next resolver milestone adds the SDK dependency and signed operation submission.

## Security model

Resolver responses are untrusted data until verified. A credential verifier should:

1. read `issuerIdentity` and `issuanceStateHash` from the signed native credential;
2. resolve that exact historical state;
3. canonicalize/hash the returned state and require equality with `issuanceStateHash`;
4. verify the credential against that historical state's AssertionPolicy.

This prevents resolver substitution from changing credential authority.
