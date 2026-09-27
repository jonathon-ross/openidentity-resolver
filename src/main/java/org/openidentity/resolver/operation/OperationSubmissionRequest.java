package org.openidentity.resolver.operation;

import java.util.List;

/**
 * HTTP submission envelope carrying canonical operation bytes and detached protocol proofs.
 *
 * @param operation unpadded base64url canonical operation bytes
 * @param proofs operation authorization proofs
 * @param proofsOfPossession proposed-authority proof-of-possession proofs when required
 */
public record OperationSubmissionRequest(
    String operation, List<ProofRequest> proofs, List<ProofRequest> proofsOfPossession) {

  /**
   * Detached protocol signature proof.
   *
   * @param methodId unpadded base64url 16-byte VerificationMethodId
   * @param signature unpadded base64url raw signature bytes
   */
  public record ProofRequest(String methodId, String signature) {}
}
