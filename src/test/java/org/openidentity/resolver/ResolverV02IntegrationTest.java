package org.openidentity.resolver;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.fasterxml.jackson.databind.*;
import java.io.InputStream;
import java.util.*;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

@SpringBootTest
@AutoConfigureMockMvc
@Testcontainers
class ResolverV02IntegrationTest {
  private static final ObjectMapper JSON = new ObjectMapper();

  @Container
  static final PostgreSQLContainer<?> POSTGRES =
      new PostgreSQLContainer<>("postgres:17")
          .withDatabaseName("openidentity")
          .withUsername("openidentity")
          .withPassword("openidentity");

  @DynamicPropertySource
  static void database(DynamicPropertyRegistry registry) {
    registry.add("spring.datasource.url", POSTGRES::getJdbcUrl);
    registry.add("spring.datasource.username", POSTGRES::getUsername);
    registry.add("spring.datasource.password", POSTGRES::getPassword);
  }

  @Autowired MockMvc mvc;

  @Test
  void normativeV02CreatePersistsAndResolvesImmutableState() throws Exception {
    JsonNode vector = v02();
    String identity = vector.path("identityHex").asText();
    String expectedHash = vector.path("stateHashHex").asText();
    String request = request(vector);

    mvc.perform(
            post("/v1/operations")
                .contentType("application/json")
                .content(request))
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

    mvc.perform(
            post("/v1/operations")
                .contentType("application/json")
                .content(request))
        .andExpect(status().isConflict())
        .andExpect(jsonPath("$.error").value("IDENTITY_ALREADY_EXISTS"));
  }

  private static JsonNode v02() throws Exception {
    try (InputStream in =
        ResolverV02IntegrationTest.class.getResourceAsStream(
            "/openidentity-v0.1.1/cryptographic-agility-v0.1.json")) {
      JsonNode root = JSON.readTree(Objects.requireNonNull(in));
      for (JsonNode vector : root.path("valid")) {
        if ("V02".equals(vector.path("id").asText())) return vector;
      }
      throw new AssertionError("V02 not found");
    }
  }

  private static String request(JsonNode v) throws Exception {
    Map<String, Object> body =
        Map.of(
            "operation",
            b64(v, "operationBytesHex"),
            "proofs",
            List.of(
                Map.of(
                    "methodId", b64(v, "ed25519MethodIdHex"),
                    "signature", b64(v, "ed25519SignatureHex")),
                Map.of(
                    "methodId", b64(v, "mlDsa65MethodIdHex"),
                    "signature", b64(v, "mlDsa65SignatureHex"))));
    return JSON.writeValueAsString(body);
  }

  private static String b64(JsonNode v, String field) {
    return Base64.getUrlEncoder()
        .withoutPadding()
        .encodeToString(HexFormat.of().parseHex(v.path(field).asText()));
  }
}
