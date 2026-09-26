package org.openidentity.resolver.operation;

import java.util.*;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.*;
import org.openidentity.crypto.SignatureProof;
import org.openidentity.operations.*;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class OperationSubmissionService {
  private final JdbcClient jdbc;

  public OperationSubmissionService(JdbcClient jdbc) {
    this.jdbc = jdbc;
  }

  @Transactional
  public OperationSubmissionResponse submit(OperationSubmissionRequest request) {
    if (request == null || request.operation() == null) {
      throw new OperationSubmissionException("INVALID_SUBMISSION", "operation is required");
    }

    byte[] operationBytes = decodeBase64Url(request.operation(), "operation");
    OpenIdentityOperation decoded;
    try {
      decoded = OpenIdentityOperationDecoder.decode(operationBytes);
    } catch (IllegalArgumentException e) {
      throw new OperationSubmissionException("INVALID_OPERATION", e.getMessage());
    }

    if (!(decoded instanceof CreateOperation create)) {
      throw new OperationSubmissionException(
          "UNSUPPORTED_OPERATION", "Only CREATE is accepted by this resolver milestone");
    }

    List<SignatureProof> proofs = decodeProofs(request.proofs());
    IdentityStateV1 state;
    try {
      state = CreateTransition.apply(create, proofs);
    } catch (OpenIdentityException e) {
      throw new OperationSubmissionException(e.error().name(), e.getMessage());
    } catch (IllegalArgumentException e) {
      throw new OperationSubmissionException("INVALID_OPERATION", e.getMessage());
    }

    byte[] stateBytes = OpenIdentityCborEncoder.encodeState(state);
    StateHash stateHash = StateHash.fromStateBytes(stateBytes);

    try {
      int inserted =
          jdbc.sql("""
                  INSERT INTO identity_state
                    (state_hash, identity_id, sequence, state_version, status, canonical_state_bytes)
                  VALUES
                    (:stateHash, :identityId, :sequence, :stateVersion, :status, :stateBytes)
                  """)
              .param("stateHash", stateHash.bytes())
              .param("identityId", state.identity().bytes())
              .param("sequence", state.sequence().value())
              .param("stateVersion", state.stateVersion())
              .param("status", state.status().code())
              .param("stateBytes", stateBytes)
              .update();
      if (inserted != 1) throw new IllegalStateException("Identity state insert did not affect one row");

      jdbc.sql("""
              INSERT INTO identity_operation
                (identity_id, sequence, operation_type, canonical_operation_bytes, resulting_state_hash)
              VALUES
                (:identityId, :sequence, :operationType, :operationBytes, :stateHash)
              """)
          .param("identityId", state.identity().bytes())
          .param("sequence", state.sequence().value())
          .param("operationType", create.operationType().code())
          .param("operationBytes", operationBytes)
          .param("stateHash", stateHash.bytes())
          .update();
    } catch (DuplicateKeyException e) {
      throw new OperationSubmissionException(
          "IDENTITY_ALREADY_EXISTS", "CREATE identity or operation already exists");
    }

    return new OperationSubmissionResponse(
        HexSupport.encode(state.identity().bytes()),
        state.sequence().value(),
        HexSupport.encode(stateHash.bytes()),
        state.stateVersion(),
        state.status().code());
  }

  private List<SignatureProof> decodeProofs(List<OperationSubmissionRequest.ProofRequest> submitted) {
    if (submitted == null) return List.of();
    ArrayList<SignatureProof> proofs = new ArrayList<>(submitted.size());
    for (var proof : submitted) {
      if (proof == null || proof.methodId() == null || proof.signature() == null) {
        throw new OperationSubmissionException("INVALID_PROOF", "proof methodId and signature are required");
      }
      byte[] methodId = decodeBase64Url(proof.methodId(), "methodId");
      byte[] signature = decodeBase64Url(proof.signature(), "signature");
      try {
        proofs.add(new SignatureProof(VerificationMethodId.of(methodId), signature));
      } catch (IllegalArgumentException e) {
        throw new OperationSubmissionException("INVALID_PROOF", e.getMessage());
      }
    }
    return List.copyOf(proofs);
  }

  private byte[] decodeBase64Url(String value, String field) {
    try {
      return Base64.getUrlDecoder().decode(value);
    } catch (IllegalArgumentException e) {
      throw new OperationSubmissionException(
          "INVALID_SUBMISSION", field + " must be unpadded base64url");
    }
  }

  private static final class HexSupport {
    private static final java.util.HexFormat HEX = java.util.HexFormat.of();
    static String encode(byte[] bytes) { return HEX.formatHex(bytes); }
  }
}
