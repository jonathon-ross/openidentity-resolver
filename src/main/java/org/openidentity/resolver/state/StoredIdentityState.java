package org.openidentity.resolver.state;

import java.math.BigInteger;
import java.time.Instant;

/**
 * Immutable persisted canonical OpenIdentity state plus indexed resolution metadata.
 *
 * @param stateHash raw 34-byte StateHash Multihash
 * @param identityId raw 32-byte IdentityId
 * @param sequence identity-state sequence
 * @param stateVersion IdentityState schema version
 * @param status protocol status code
 * @param canonicalStateBytes authoritative deterministic-CBOR state bytes
 * @param createdAt resolver persistence timestamp
 */
public record StoredIdentityState(
    byte[] stateHash,
    byte[] identityId,
    BigInteger sequence,
    int stateVersion,
    int status,
    byte[] canonicalStateBytes,
    Instant createdAt) {

  /** Defensively copies all mutable byte-array components. */
  public StoredIdentityState {
    stateHash = stateHash.clone();
    identityId = identityId.clone();
    canonicalStateBytes = canonicalStateBytes.clone();
  }

  /**
   * Returns a defensive copy of the raw StateHash bytes.
   *
   * @return copied StateHash bytes
   */
  @Override
  public byte[] stateHash() {
    return stateHash.clone();
  }

  /**
   * Returns a defensive copy of the raw IdentityId bytes.
   *
   * @return copied IdentityId bytes
   */
  @Override
  public byte[] identityId() {
    return identityId.clone();
  }

  /**
   * Returns a defensive copy of the authoritative canonical state bytes.
   *
   * @return copied canonical state bytes
   */
  @Override
  public byte[] canonicalStateBytes() {
    return canonicalStateBytes.clone();
  }
}
