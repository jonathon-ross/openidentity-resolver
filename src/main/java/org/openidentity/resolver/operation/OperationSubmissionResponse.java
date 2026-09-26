package org.openidentity.resolver.operation;

import java.math.BigInteger;

/** Result of an accepted OpenIdentity operation. */
public record OperationSubmissionResponse(
    String identity, BigInteger sequence, String stateHash, int stateVersion, int status) {}
