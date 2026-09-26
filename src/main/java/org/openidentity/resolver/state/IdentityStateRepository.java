package org.openidentity.resolver.state;

import java.util.Optional;

/** Read access to immutable identity-state history. */
public interface IdentityStateRepository {
  Optional<StoredIdentityState> findCurrent(byte[] identityId);
  Optional<StoredIdentityState> findHistorical(byte[] identityId, byte[] stateHash);
}
