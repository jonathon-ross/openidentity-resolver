package org.openidentity.resolver.state;

import java.util.Optional;

/** Read access to immutable identity-state history. */
public interface IdentityStateRepository {
  /**
   * Finds the highest-sequence state for an identity.
   *
   * @param identityId raw 32-byte IdentityId
   * @return current state when known
   */
  Optional<StoredIdentityState> findCurrent(byte[] identityId);

  /**
   * Finds an exact historical identity/state-hash pair.
   *
   * @param identityId raw 32-byte IdentityId
   * @param stateHash raw 34-byte StateHash Multihash
   * @return matching immutable historical state when known
   */
  Optional<StoredIdentityState> findHistorical(byte[] identityId, byte[] stateHash);
}
