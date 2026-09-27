package org.openidentity.resolver.web;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Base64;
import org.openidentity.resolver.state.StoredIdentityState;

/**
 * HTTP representation of a resolved canonical OpenIdentity state.
 *
 * @param identity hexadecimal 32-byte IdentityId
 * @param sequence state sequence
 * @param stateHash hexadecimal 34-byte SHA2-256 Multihash
 * @param stateVersion IdentityState schema version
 * @param status protocol status code
 * @param canonicalState unpadded base64url deterministic-CBOR state bytes
 * @param createdAt resolver persistence timestamp
 */
public record ResolutionResponse(
    String identity,
    BigInteger sequence,
    String stateHash,
    int stateVersion,
    int status,
    String canonicalState,
    Instant createdAt) {

  static ResolutionResponse from(StoredIdentityState state) {
    return new ResolutionResponse(
        Hex.encode(state.identityId()),
        state.sequence(),
        Hex.encode(state.stateHash()),
        state.stateVersion(),
        state.status(),
        Base64.getUrlEncoder().withoutPadding().encodeToString(state.canonicalStateBytes()),
        state.createdAt());
  }
}
