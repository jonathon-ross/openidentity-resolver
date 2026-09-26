package org.openidentity.resolver.operation;

import java.util.List;

/** HTTP submission envelope carrying canonical operation bytes and detached authorization proofs. */
public record OperationSubmissionRequest(String operation, List<ProofRequest> proofs) {
  public record ProofRequest(String methodId, String signature) {}
}
