package org.openidentity.resolver;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.security.*;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.*;
import org.openidentity.crypto.*;
import org.openidentity.operations.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.transaction.annotation.Transactional;

@SpringBootTest(
    properties = {
      "spring.datasource.url=jdbc:postgresql://localhost:5433/openidentity_test",
      "spring.datasource.username=openidentity",
      "spring.datasource.password=openidentity"
    })
@AutoConfigureMockMvc
@Transactional
class RecoveryIntegrationTest {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final HexFormat HEX = HexFormat.of();

  @Autowired MockMvc mvc;

  @Test
  void createThenRecoverRotatesControllerAndRecoveryCommitment() throws Exception {
    Key oldController = key("000102030405060708090a0b0c0d0e0f");
    Key recovery = key("101112131415161718191a1b1c1d1e1f");
    Key newController = key("202122232425262728292a2b2c2d2e2f");
    Key nextRecovery = key("303132333435363738393a3b3c3d3e3f");

    IdentityId identity =
        IdentityId.of(
            HEX.parseHex("404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f"));
    RecoveryPolicy recoveryPolicy = RecoveryPolicy.single(recovery.method());
    RecoveryPolicy nextRecoveryPolicy = RecoveryPolicy.single(nextRecovery.method());

    CreateOperation create =
        new CreateOperation(
            identity,
            ControllerPolicy.single(oldController.method()),
            commitment(recoveryPolicy));
    SignatureProof createProof =
        sign(oldController, SigningInputs.operation(create.encode()));

    String createResponse =
        mvc.perform(
                post("/v1/operations")
                    .contentType("application/json")
                    .content(request(create.encode(), List.of(createProof), List.of())))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.sequence").value(1))
            .andReturn()
            .getResponse()
            .getContentAsString();

    String firstHash = JSON.readTree(createResponse).path("stateHash").asText();

    RecoverOperation recover =
        new RecoverOperation(
            identity,
            Sequence.of(2),
            new StateHash(MultihashSha256.of(HEX.parseHex(firstHash))),
            ControllerPolicy.single(newController.method()),
            recoveryPolicy,
            commitment(nextRecoveryPolicy));

    SignatureProof recoveryProof =
        sign(
            recovery,
            SigningInputs.recovery(recover.encode(), recovery.method().id()));
    SignatureProof controllerPop =
        sign(
            newController,
            SigningInputs.controllerProof(recover.encode(), newController.method().id()));

    String recoveryResponse =
        mvc.perform(
                post("/v1/operations")
                    .contentType("application/json")
                    .content(
                        request(
                            recover.encode(),
                            List.of(recoveryProof),
                            List.of(controllerPop))))
            .andExpect(status().isCreated())
            .andExpect(jsonPath("$.sequence").value(2))
            .andExpect(jsonPath("$.stateVersion").value(1))
            .andExpect(jsonPath("$.status").value(1))
            .andReturn()
            .getResponse()
            .getContentAsString();

    String secondHash = JSON.readTree(recoveryResponse).path("stateHash").asText();
    String identityHex = HEX.formatHex(identity.bytes());

    mvc.perform(get("/v1/identities/{identity}", identityHex))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.sequence").value(2))
        .andExpect(jsonPath("$.stateHash").value(secondHash));

    mvc.perform(get("/v1/identities/{identity}/states/{hash}", identityHex, firstHash))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.sequence").value(1));

    mvc.perform(get("/v1/identities/{identity}/states/{hash}", identityHex, secondHash))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.sequence").value(2));
  }

  private static RecoveryCommitment commitment(RecoveryPolicy policy) {
    return new RecoveryCommitment(
        MultihashSha256.digest(OpenIdentityCborEncoder.encodeRecoveryPolicy(policy)));
  }

  private static String request(
      byte[] operation, List<SignatureProof> proofs, List<SignatureProof> pops)
      throws Exception {
    return JSON.writeValueAsString(
        Map.of(
            "operation", b64(operation),
            "proofs", proofs.stream().map(RecoveryIntegrationTest::proof).toList(),
            "proofsOfPossession", pops.stream().map(RecoveryIntegrationTest::proof).toList()));
  }

  private static Map<String, String> proof(SignatureProof proof) {
    return Map.of(
        "methodId", b64(proof.methodId().bytes()),
        "signature", b64(proof.signature()));
  }

  private static SignatureProof sign(Key key, byte[] input) throws Exception {
    Signature signer = Signature.getInstance("Ed25519");
    signer.initSign(key.pair().getPrivate());
    signer.update(input);
    return new SignatureProof(key.method().id(), signer.sign());
  }

  private static Key key(String methodIdHex) throws Exception {
    KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    return new Key(
        pair,
        new VerificationMethod(
            VerificationMethodId.of(HEX.parseHex(methodIdHex)),
            Ed25519Key.of(raw((EdECPublicKey) pair.getPublic()))));
  }

  private static byte[] raw(EdECPublicKey key) {
    EdECPoint point = key.getPoint();
    byte[] y = point.getY().toByteArray();
    byte[] out = new byte[32];
    for (int i = 0; i < Math.min(y.length, 32); i++) out[i] = y[y.length - 1 - i];
    if (point.isXOdd()) out[31] |= (byte) 0x80;
    return out;
  }

  private static String b64(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private record Key(KeyPair pair, VerificationMethod method) {}
}
