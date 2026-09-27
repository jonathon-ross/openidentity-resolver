package org.openidentity.resolver.operation;

import java.math.BigInteger;

/**
 * Result metadata for an accepted OpenIdentity operation.
 *
 * @param identity hexadecimal 32-byte IdentityId
 * @param sequence resulting identity-state sequence
 * @param stateHash hexadecimal resulting 34-byte SHA2-256 Multihash
 * @param stateVersion resulting IdentityState schema version
 * @param status resulting protocol status code
 */
public record OperationSubmissionResponse(
    String identity, BigInteger sequence, String stateHash, int stateVersion, int status) {}
