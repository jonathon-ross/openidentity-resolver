package org.openidentity.resolver.state;

import java.math.BigInteger;
import java.time.Instant;

/** Immutable persisted canonical OpenIdentity state plus indexed resolution metadata. */
public record StoredIdentityState(
    byte[] stateHash,
    byte[] identityId,
    BigInteger sequence,
    int stateVersion,
    int status,
    byte[] canonicalStateBytes,
    Instant createdAt) {

  public StoredIdentityState {
    stateHash = stateHash.clone();
    identityId = identityId.clone();
    canonicalStateBytes = canonicalStateBytes.clone();
  }

  @Override
  public byte[] stateHash() {
    return stateHash.clone();
  }

  @Override
  public byte[] identityId() {
    return identityId.clone();
  }

  @Override
  public byte[] canonicalStateBytes() {
    return canonicalStateBytes.clone();
  }
}
