package org.openidentity.resolver;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.InputStream;
import java.util.Base64;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import org.junit.jupiter.api.Test;
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
class ResolverV02IntegrationTest {
  private static final ObjectMapper JSON = new ObjectMapper();

  @Autowired MockMvc mvc;

  @Test
  void normativeV02CreatePersistsAndResolvesImmutableState() throws Exception {
    JsonNode vector = v02();
    String identity = vector.path("identityHex").asText();
    String expectedHash = vector.path("stateHashHex").asText();
    String request = request(vector);

    mvc.perform(post("/v1/operations").contentType("application/json").content(request))
        .andExpect(status().isCreated())
        .andExpect(jsonPath("$.identity").value(identity))
        .andExpect(jsonPath("$.sequence").value(1))
        .andExpect(jsonPath("$.stateHash").value(expectedHash))
        .andExpect(jsonPath("$.stateVersion").value(1))
        .andExpect(jsonPath("$.status").value(1));

    mvc.perform(get("/v1/identities/{identity}", identity))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.sequence").value(1))
        .andExpect(jsonPath("$.stateHash").value(expectedHash));

    mvc.perform(get("/v1/identities/{identity}/states/{hash}", identity, expectedHash))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.sequence").value(1))
        .andExpect(jsonPath("$.stateHash").value(expectedHash));

    mvc.perform(post("/v1/operations").contentType("application/json").content(request))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.error").value("IDENTITY_ALREADY_EXISTS"));
  }

  @Test
  void normativeV02ThenV04MaintainsImmutableTwoStateChain() throws Exception {
    JsonNode create = vector("V02");
    JsonNode rotate = vector("V04");
    String identity = create.path("identityHex").asText();
    String firstHash = create.path("stateHashHex").asText();
    String secondHash = rotate.path("resultingStateHashHex").asText();

    mvc.perform(post("/v1/operations").contentType("application/json").content(request(create)))
        .andExpect(status().isCreated());

    mvc.perform(
            post("/v1/operations")
                .contentType("application/json")
                .content(rotateRequest(rotate)))
        .andExpect(status().isCreated())
        .andExpect(jsonPath("$.sequence").value(2))
        .andExpect(jsonPath("$.stateHash").value(secondHash));

    mvc.perform(get("/v1/identities/{identity}", identity))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.sequence").value(2))
        .andExpect(jsonPath("$.stateHash").value(secondHash));

    mvc.perform(get("/v1/identities/{identity}/states/{hash}", identity, firstHash))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.sequence").value(1));

    mvc.perform(get("/v1/identities/{identity}/states/{hash}", identity, secondHash))
        .andExpect(status().isOk())
        .andExpect(jsonPath("$.sequence").value(2));

    mvc.perform(
            post("/v1/operations")
                .contentType("application/json")
                .content(rotateRequest(rotate)))
        .andExpect(status().isBadRequest());
  }

  private static JsonNode v02() throws Exception {
    try (InputStream in =
        ResolverV02IntegrationTest.class.getResourceAsStream(
            "/openidentity-v0.1.1/cryptographic-agility-v0.1.json")) {
      JsonNode root = JSON.readTree(Objects.requireNonNull(in));
      for (JsonNode vector : root.path("valid")) {
        if ("V02".equals(vector.path("id").asText())) {
          return vector;
        }
      }
      throw new AssertionError("V02 not found");
    }
  }

  private static JsonNode vector(String id) throws Exception {
    try (InputStream in =
        ResolverV02IntegrationTest.class.getResourceAsStream(
            "/openidentity-v0.1.1/cryptographic-agility-v0.1.json")) {
      JsonNode root = JSON.readTree(Objects.requireNonNull(in));
      for (JsonNode vector : root.path("valid")) {
        if (id.equals(vector.path("id").asText())) return vector;
      }
      throw new AssertionError(id + " not found");
    }
  }

  private static String rotateRequest(JsonNode vector) throws Exception {
    Map<String, Object> body =
        Map.of(
            "operation",
            b64(vector, "operationBytesHex"),
            "proofs",
            List.of(
                Map.of(
                    "methodId", b64(vector, "oldEd25519MethodIdHex"),
                    "signature", b64(vector, "oldEd25519AuthorizationSignatureHex")),
                Map.of(
                    "methodId", b64(vector, "oldMlDsa65MethodIdHex"),
                    "signature", b64(vector, "oldMlDsa65AuthorizationSignatureHex"))),
            "proofsOfPossession",
            List.of(
                Map.of(
                    "methodId", b64(vector, "newEd25519MethodIdHex"),
                    "signature", b64(vector, "newEd25519PopSignatureHex")),
                Map.of(
                    "methodId", b64(vector, "newMlDsa65MethodIdHex"),
                    "signature", b64(vector, "newMlDsa65PopSignatureHex"))));
    return JSON.writeValueAsString(body);
  }

  private static String request(JsonNode vector) throws Exception {
    Map<String, Object> body =
        Map.of(
            "operation",
            b64(vector, "operationBytesHex"),
            "proofs",
            List.of(
                Map.of(
                    "methodId",
                    b64(vector, "ed25519MethodIdHex"),
                    "signature",
                    b64(vector, "ed25519SignatureHex")),
                Map.of(
                    "methodId",
                    b64(vector, "mlDsa65MethodIdHex"),
                    "signature",
                    b64(vector, "mlDsa65SignatureHex"))));
    return JSON.writeValueAsString(body);
  }

  private static String b64(JsonNode vector, String field) {
    return Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString(HexFormat.of().parseHex(vector.path(field).asText()));
  }
}
