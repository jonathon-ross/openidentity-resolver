package org.openidentity.resolver.operation;

import java.util.*;
import org.openidentity.cbor.OpenIdentityCborDecoder;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.*;
import org.openidentity.crypto.SignatureProof;
import org.openidentity.operations.*;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/** Verifies protocol operations, applies SDK transitions, and atomically appends state history. */
@Service
public class OperationSubmissionService {
  private final JdbcClient jdbc;

  /** @param jdbc configured resolver database client */
  public OperationSubmissionService(JdbcClient jdbc) {
    this.jdbc = jdbc;
  }

  /**
   * Decodes, verifies, applies, and persists one protocol operation.
   *
   * @param request canonical operation and detached proofs
   * @return resulting state metadata
   * @throws OperationSubmissionException when decoding, authorization, transition, or persistence fails
   */
  @Transactional
  public OperationSubmissionResponse submit(OperationSubmissionRequest request) {
    if (request == null || request.operation() == null) {
      throw new OperationSubmissionException("INVALID_SUBMISSION", "operation is required");
    }

    byte[] operationBytes = decodeBase64Url(request.operation(), "operation");
    OpenIdentityOperation operation = decodeOperation(operationBytes);
    List<SignatureProof> authorization = decodeProofs(request.proofs());
    List<SignatureProof> possession = decodeProofs(request.proofsOfPossession());

    IdentityState resultingState =
        switch (operation) {
          case CreateOperation create -> applyCreate(create, authorization);
          case RotateControllerOperation rotate -> applyRotate(rotate, authorization, possession);
          case SetAssertionPolicyOperation assertion ->
              applyAssertion(assertion, authorization, possession);
          case DeactivateOperation deactivate -> applyDeactivate(deactivate, authorization);
          case RecoverOperation recover -> applyRecover(recover, authorization, possession);
          default ->
              throw new OperationSubmissionException(
                  "UNSUPPORTED_OPERATION",
                  "Resolver accepts all OpenIdentity Protocol v0.1.1 operation types");
        };

    return persist(operation, operationBytes, resultingState);
  }

  private IdentityStateV1 applyCreate(
      CreateOperation operation, List<SignatureProof> authorization) {
    try {
      return CreateTransition.apply(operation, authorization);
    } catch (OpenIdentityException e) {
      throw protocolFailure(e);
    } catch (IllegalArgumentException e) {
      throw invalidOperation(e);
    }
  }

  private IdentityState applyRotate(
      RotateControllerOperation operation,
      List<SignatureProof> authorization,
      List<SignatureProof> possession) {
    IdentityState current = loadCurrent(operation.identity());
    try {
      return RotateControllerTransition.apply(current, operation, authorization, possession);
    } catch (OpenIdentityException e) {
      throw protocolFailure(e);
    } catch (IllegalArgumentException e) {
      throw invalidOperation(e);
    }
  }

  private IdentityState applyAssertion(
      SetAssertionPolicyOperation operation,
      List<SignatureProof> authorization,
      List<SignatureProof> possession) {
    IdentityState current = loadCurrent(operation.identity());
    try {
      return SetAssertionPolicyTransition.apply(current, operation, authorization, possession);
    } catch (OpenIdentityException e) {
      throw protocolFailure(e);
    } catch (IllegalArgumentException e) {
      throw invalidOperation(e);
    }
  }

  private IdentityState applyDeactivate(
      DeactivateOperation operation, List<SignatureProof> authorization) {
    IdentityState current = loadCurrent(operation.identity());
    try {
      return DeactivateTransition.apply(current, operation, authorization);
    } catch (OpenIdentityException e) {
      throw protocolFailure(e);
    } catch (IllegalArgumentException e) {
      throw invalidOperation(e);
    }
  }

  private IdentityState applyRecover(
      RecoverOperation operation,
      List<SignatureProof> recoveryProofs,
      List<SignatureProof> controllerPossession) {
    IdentityState current = loadCurrent(operation.identity());
    try {
      return RecoverTransition.apply(current, operation, recoveryProofs, controllerPossession);
    } catch (OpenIdentityException e) {
      throw protocolFailure(e);
    } catch (IllegalArgumentException e) {
      throw invalidOperation(e);
    }
  }

  private IdentityState loadCurrent(IdentityId identity) {
    return jdbc.sql(
            """
            SELECT canonical_state_bytes
            FROM identity_state
            WHERE identity_id = :identityId
            ORDER BY sequence DESC
            LIMIT 1
            """)
        .param("identityId", identity.bytes())
        .query((rs, rowNum) -> OpenIdentityCborDecoder.decodeState(rs.getBytes(1)))
        .optional()
        .orElseThrow(
            () ->
                new OperationSubmissionException(
                    "IDENTITY_NOT_FOUND", "No current state exists for operation identity"));
  }

  private OperationSubmissionResponse persist(
      OpenIdentityOperation operation, byte[] operationBytes, IdentityState state) {
    byte[] stateBytes = OpenIdentityCborEncoder.encodeState(state);
    StateHash stateHash = StateHash.fromStateBytes(stateBytes);

    try {
      jdbc.sql(
              """
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

      jdbc.sql(
              """
              INSERT INTO identity_operation
                (identity_id, sequence, operation_type, canonical_operation_bytes, resulting_state_hash)
              VALUES
                (:identityId, :sequence, :operationType, :operationBytes, :stateHash)
              """)
          .param("identityId", state.identity().bytes())
          .param("sequence", state.sequence().value())
          .param("operationType", operation.operationType().code())
          .param("operationBytes", operationBytes)
          .param("stateHash", stateHash.bytes())
          .update();
    } catch (DuplicateKeyException e) {
      String code =
          operation instanceof CreateOperation ? "IDENTITY_ALREADY_EXISTS" : "OPERATION_CONFLICT";
      throw new OperationSubmissionException(
          code, "Identity sequence, state, or operation already exists");
    }

    return new OperationSubmissionResponse(
        HexSupport.encode(state.identity().bytes()),
        state.sequence().value(),
        HexSupport.encode(stateHash.bytes()),
        state.stateVersion(),
        state.status().code());
  }

  private OpenIdentityOperation decodeOperation(byte[] operationBytes) {
    try {
      return OpenIdentityOperationDecoder.decode(operationBytes);
    } catch (IllegalArgumentException e) {
      throw invalidOperation(e);
    }
  }

  private OperationSubmissionException protocolFailure(OpenIdentityException e) {
    return new OperationSubmissionException(e.error().name(), e.getMessage());
  }

  private OperationSubmissionException invalidOperation(IllegalArgumentException e) {
    return new OperationSubmissionException(
        "INVALID_OPERATION", e.getMessage() == null ? "Invalid operation" : e.getMessage());
  }

  private List<SignatureProof> decodeProofs(
      List<OperationSubmissionRequest.ProofRequest> submitted) {
    if (submitted == null) return List.of();
    ArrayList<SignatureProof> proofs = new ArrayList<>(submitted.size());
    for (var proof : submitted) {
      if (proof == null || proof.methodId() == null || proof.signature() == null) {
        throw new OperationSubmissionException(
            "INVALID_PROOF", "proof methodId and signature are required");
      }
      try {
        proofs.add(
            new SignatureProof(
                VerificationMethodId.of(decodeBase64Url(proof.methodId(), "methodId")),
                decodeBase64Url(proof.signature(), "signature")));
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

    static String encode(byte[] bytes) {
      return HEX.formatHex(bytes);
    }
  }
}
