package org.openidentity.resolver.web;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Base64;
import org.openidentity.resolver.state.StoredIdentityState;

/** JSON representation of resolved canonical state and indexing metadata. */
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
