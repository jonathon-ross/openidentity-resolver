package org.openidentity.resolver;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.*;
import java.security.*;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.time.Instant;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.openidentity.cbor.*;
import org.openidentity.core.*;
import org.openidentity.credentials.*;
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
class HistoricalCredentialIntegrationTest {
  private static final ObjectMapper JSON = new ObjectMapper();
  private static final HexFormat HEX = HexFormat.of();

  @Autowired MockMvc mvc;

  @Test
  void credentialRemainsValidAgainstHistoricalAuthorityAfterAssertionRotation() throws Exception {
    Key controller = key("000102030405060708090a0b0c0d0e0f");
    Key assertion1 = key("101112131415161718191a1b1c1d1e1f");
    Key assertion2 = key("202122232425262728292a2b2c2d2e2f");
    IdentityId identity =
        IdentityId.of(
            HEX.parseHex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f"));

    CreateOperation create =
        new CreateOperation(identity, ControllerPolicy.single(controller.method()), null);
    String createResponse =
        submit(
            create.encode(),
            List.of(sign(controller, SigningInputs.operation(create.encode()))),
            List.of(),
            201);
    String hash1 = JSON.readTree(createResponse).path("stateHash").asText();

    SetAssertionPolicyOperation install =
        new SetAssertionPolicyOperation(
            identity,
            Sequence.of(2),
            stateHash(hash1),
            AssertionPolicy.single(assertion1.method()));
    String installResponse =
        submit(
            install.encode(),
            List.of(sign(controller, SigningInputs.operation(install.encode()))),
            List.of(
                sign(
                    assertion1,
                    SigningInputs.controllerProof(install.encode(), assertion1.method().id()))),
            201);
    String issuanceHashHex = JSON.readTree(installResponse).path("stateHash").asText();
    StateHash issuanceHash = stateHash(issuanceHashHex);

    byte[] credentialId = new byte[32];
    Arrays.fill(credentialId, (byte) 0x42);
    long validFrom = Instant.now().getEpochSecond();
    OpenIdentityCredential credential =
        new OpenIdentityCredential(
            credentialId,
            identity,
            issuanceHash,
            validFrom,
            validFrom + 3600,
            "https://openidentity.org/credentials/basic/v1",
            "subject-1".getBytes(java.nio.charset.StandardCharsets.UTF_8),
            Map.of("name", "Historical authority integration test"));
    byte[] credentialBytes = credential.encode();
    SignatureProof credentialProof =
        sign(assertion1, CredentialSigningInputs.credential(credentialBytes));

    SetAssertionPolicyOperation rotateAssertion =
        new SetAssertionPolicyOperation(
            identity,
            Sequence.of(3),
            issuanceHash,
            AssertionPolicy.single(assertion2.method()));
    String rotationResponse =
        submit(
            rotateAssertion.encode(),
            List.of(sign(controller, SigningInputs.operation(rotateAssertion.encode()))),
            List.of(
                sign(
                    assertion2,
                    SigningInputs.controllerProof(
                        rotateAssertion.encode(), assertion2.method().id()))),
            201);
    String currentHash = JSON.readTree(rotationResponse).path("stateHash").asText();

    String identityHex = HEX.formatHex(identity.bytes());
    String historicalJson =
        mvc.perform(
                get(
                    "/v1/identities/{identity}/states/{hash}",
                    identityHex,
                    issuanceHashHex))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.sequence").value(2))
            .andReturn()
            .getResponse()
            .getContentAsString();

    mvc.perform(get("/v1/identities/{identity}", identityHex))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.sequence").value(3))
        .andExpect(jsonPath("$.stateHash").value(currentHash));

    byte[] historicalBytes =
        Base64.getUrlDecoder()
            .decode(JSON.readTree(historicalJson).path("canonicalState").asText());
    IdentityState historical = OpenIdentityCborDecoder.decodeState(historicalBytes);

    VerificationResult result =
        CredentialVerifier.verifyResult(
            credentialBytes, identity, issuanceHash, historical, List.of(credentialProof));
    assertTrue(result.valid(), () -> String.valueOf(result));
  }

  private String submit(
      byte[] operation,
      List<SignatureProof> proofs,
      List<SignatureProof> pops,
      int expectedStatus)
      throws Exception {
    String body =
        JSON.writeValueAsString(
            Map.of(
                "operation", b64(operation),
                "proofs", proofs.stream().map(HistoricalCredentialIntegrationTest::proof).toList(),
                "proofsOfPossession",
                pops.stream().map(HistoricalCredentialIntegrationTest::proof).toList()));
    return mvc.perform(post("/v1/operations").contentType("application/json").content(body))
        .andExpect(status().is(expectedStatus))
        .andReturn()
        .getResponse()
        .getContentAsString();
  }

  private static StateHash stateHash(String hex) {
    return new StateHash(MultihashSha256.of(HEX.parseHex(hex)));
  }

  private static Map<String, String> proof(SignatureProof proof) {
    return Map.of("methodId", b64(proof.methodId().bytes()), "signature", b64(proof.signature()));
  }

  private static SignatureProof sign(Key key, byte[] input) throws Exception {
    Signature signer = Signature.getInstance("Ed25519");
    signer.initSign(key.pair().getPrivate());
    signer.update(input);
    return new SignatureProof(key.method().id(), signer.sign());
  }

  private static Key key(String id) throws Exception {
    KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    return new Key(
        pair,
        new VerificationMethod(
            VerificationMethodId.of(HEX.parseHex(id)),
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
