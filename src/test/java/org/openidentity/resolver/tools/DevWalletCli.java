package org.openidentity.resolver.tools;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.EdECPoint;
import java.util.*;
import org.openidentity.core.*;
import org.openidentity.crypto.SignatureProof;
import org.openidentity.crypto.SigningInputs;
import org.openidentity.credentials.CredentialSigningInputs;
import org.openidentity.credentials.OpenIdentityCredential;
import org.openidentity.credentials.CredentialVerifier;
import org.openidentity.cbor.OpenIdentityCborDecoder;
import org.openidentity.operations.CreateOperation;
import org.openidentity.operations.RotateControllerOperation;
import org.openidentity.operations.SetAssertionPolicyOperation;

/**
 * Local development wallet CLI for exercising resolver lifecycle operations.
 *
 * <p>Wallet files contain private keys and are stored under the gitignored .openidentity directory.
 */
public final class DevWalletCli {
  private static final ObjectMapper JSON =
      new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
  private static final Path WALLET = Path.of(".openidentity", "dev-wallet.json");
  private static final HexFormat HEX = HexFormat.of();

  private DevWalletCli() {}

  public static void main(String[] args) throws Exception {
    if (args.length < 1) usage();
    switch (args[0]) {
      case "init" -> init();
      case "create" -> create();
      case "rotate" -> {
        if (args.length != 2) usage();
        rotate(args[1]);
      }
      case "activate-controller" -> activateController();
      case "set-assertion-policy" -> {
        if (args.length != 2) usage();
        setAssertionPolicy(args[1]);
      }
      case "activate-assertion" -> activateAssertion();
      case "discard-pending-assertion" -> discardPendingAssertion();
      case "issue-credential" -> {
        if (args.length != 2) usage();
        issueCredential(args[1]);
      }
      case "rotate-assertion" -> {
        if (args.length != 2) usage();
        rotateAssertion(args[1]);
      }
      case "verify-credential" -> {
        if (args.length > 2) usage();
        verifyCredential(args.length == 2 ? args[1] : "http://localhost:8080");
      }
      default -> usage();
    }
  }

  private static void init() throws Exception {
    if (Files.exists(WALLET)) {
      throw new IllegalStateException("Wallet already exists: " + WALLET);
    }
    Files.createDirectories(WALLET.getParent());

    SecureRandom random = new SecureRandom();
    byte[] identity = new byte[IdentityId.LENGTH];
    random.nextBytes(identity);

    DevWallet.KeyEntry controller = newKey("controller-1", random);
    DevWallet wallet =
        new DevWallet(
            HEX.formatHex(identity), controller.name(), null, List.of(controller), null, null);
    JSON.writeValue(WALLET.toFile(), wallet);

    System.out.println("Created local development wallet: " + WALLET);
    System.out.println("Identity: " + wallet.identityHex());
    System.out.println("Controller method: " + controller.methodIdHex());
    System.out.println("Private key material was written only to the gitignored wallet file.");
  }

  private static void create() throws Exception {
    DevWallet wallet = load();
    DevWallet.KeyEntry controller = activeController(wallet);
    IdentityId identity = IdentityId.of(HEX.parseHex(wallet.identityHex()));
    VerificationMethod method = verificationMethod(controller);

    CreateOperation operation =
        new CreateOperation(identity, ControllerPolicy.single(method), null);
    SignatureProof proof =
        sign(
            controller,
            method.id(),
            SigningInputs.operation(operation.encode()));

    Map<String, Object> request =
        Map.of(
            "operation", b64url(operation.encode()),
            "proofs",
                List.of(
                    Map.of(
                        "methodId", b64url(proof.methodId().bytes()),
                        "signature", b64url(proof.signature()))));

    System.out.println("Identity: " + wallet.identityHex());
    System.out.println(JSON.writeValueAsString(request));
  }

  private static void rotate(String currentStateHashHex) throws Exception {
    DevWallet wallet = load();
    if (wallet.pendingController() != null) {
      throw new IllegalStateException(
          "A pending controller already exists. Submit/activate it before generating another rotation.");
    }

    DevWallet.KeyEntry oldController = activeController(wallet);
    SecureRandom random = new SecureRandom();
    DevWallet.KeyEntry newController =
        newKey("controller-" + (wallet.controllers().size() + 1), random);

    VerificationMethod oldMethod = verificationMethod(oldController);
    VerificationMethod newMethod = verificationMethod(newController);
    RotateControllerOperation operation =
        new RotateControllerOperation(
            IdentityId.of(HEX.parseHex(wallet.identityHex())),
            Sequence.of(2),
            new StateHash(MultihashSha256.of(HEX.parseHex(currentStateHashHex))),
            ControllerPolicy.single(newMethod));

    SignatureProof authorization =
        sign(
            oldController,
            oldMethod.id(),
            SigningInputs.operation(operation.encode()));
    SignatureProof possession =
        sign(
            newController,
            newMethod.id(),
            SigningInputs.controllerProof(operation.encode(), newMethod.id()));

    ArrayList<DevWallet.KeyEntry> controllers = new ArrayList<>(wallet.controllers());
    controllers.add(newController);
    save(
        new DevWallet(
            wallet.identityHex(),
            wallet.activeController(),
            newController.name(),
            List.copyOf(controllers),
            wallet.assertion(),
            wallet.pendingAssertion()));

    Map<String, Object> request =
        Map.of(
            "operation",
            b64url(operation.encode()),
            "proofs",
            List.of(proofJson(authorization)),
            "proofsOfPossession",
            List.of(proofJson(possession)));

    System.out.println("Identity: " + wallet.identityHex());
    System.out.println("Pending controller: " + newController.name());
    System.out.println(JSON.writeValueAsString(request));
  }

  private static void activateController() throws Exception {
    DevWallet wallet = load();
    if (wallet.pendingController() == null) {
      throw new IllegalStateException("No pending controller exists.");
    }
    String activated = wallet.pendingController();
    save(
        new DevWallet(
            wallet.identityHex(),
            activated,
            null,
            wallet.controllers(),
            wallet.assertion(),
            wallet.pendingAssertion()));
    System.out.println("Activated controller: " + activated);
  }

  private static void setAssertionPolicy(String currentStateHashHex) throws Exception {
    DevWallet wallet = load();
    if (wallet.pendingAssertion() != null) {
      throw new IllegalStateException(
          "A pending assertion key already exists. Submit/activate it before generating another.");
    }

    DevWallet.KeyEntry controller = activeController(wallet);
    DevWallet.KeyEntry assertion = newKey("assertion-1", new SecureRandom());
    VerificationMethod controllerMethod = verificationMethod(controller);
    VerificationMethod assertionMethod = verificationMethod(assertion);

    SetAssertionPolicyOperation operation =
        new SetAssertionPolicyOperation(
            IdentityId.of(HEX.parseHex(wallet.identityHex())),
            Sequence.of(3),
            new StateHash(MultihashSha256.of(HEX.parseHex(currentStateHashHex))),
            AssertionPolicy.single(assertionMethod));

    SignatureProof authorization =
        sign(
            controller,
            controllerMethod.id(),
            SigningInputs.operation(operation.encode()));
    SignatureProof possession =
        sign(
            assertion,
            assertionMethod.id(),
            SigningInputs.controllerProof(operation.encode(), assertionMethod.id()));

    save(
        new DevWallet(
            wallet.identityHex(),
            wallet.activeController(),
            wallet.pendingController(),
            wallet.controllers(),
            wallet.assertion(),
            assertion));

    Map<String, Object> request =
        Map.of(
            "operation",
            b64url(operation.encode()),
            "proofs",
            List.of(proofJson(authorization)),
            "proofsOfPossession",
            List.of(proofJson(possession)));

    System.out.println("Identity: " + wallet.identityHex());
    System.out.println("Pending assertion key: " + assertion.name());
    System.out.println(JSON.writeValueAsString(request));
  }

  private static void activateAssertion() throws Exception {
    DevWallet wallet = load();
    if (wallet.pendingAssertion() == null) {
      throw new IllegalStateException("No pending assertion key exists.");
    }
    DevWallet.KeyEntry activated = wallet.pendingAssertion();
    save(
        new DevWallet(
            wallet.identityHex(),
            wallet.activeController(),
            wallet.pendingController(),
            wallet.controllers(),
            activated,
            null));
    System.out.println("Activated assertion key: " + activated.name());
  }

  private static void discardPendingAssertion() throws Exception {
    DevWallet wallet = load();
    if (wallet.pendingAssertion() == null) {
      throw new IllegalStateException("No pending assertion key exists.");
    }
    String discarded = wallet.pendingAssertion().name();
    save(
        new DevWallet(
            wallet.identityHex(),
            wallet.activeController(),
            wallet.pendingController(),
            wallet.controllers(),
            wallet.assertion(),
            null));
    System.out.println("Discarded pending assertion key: " + discarded);
  }

  @SuppressWarnings("unchecked")
  private static void verifyCredential(String resolverBaseUrl) throws Exception {
    Path credentialFile = WALLET.getParent().resolve("credential-1.json");
    if (!Files.exists(credentialFile)) {
      throw new IllegalStateException("Credential not found: " + credentialFile);
    }

    Map<String, Object> stored = JSON.readValue(credentialFile.toFile(), Map.class);
    String issuerHex = (String) stored.get("issuer");
    String issuanceHashHex = (String) stored.get("issuanceStateHash");
    byte[] credentialBytes =
        Base64.getUrlDecoder().decode((String) stored.get("credential"));

    List<Map<String, String>> storedProofs =
        (List<Map<String, String>>) stored.get("proofs");
    List<SignatureProof> proofs =
        storedProofs.stream()
            .map(
                proof ->
                    new SignatureProof(
                        VerificationMethodId.of(
                            Base64.getUrlDecoder().decode(proof.get("methodId"))),
                        Base64.getUrlDecoder().decode(proof.get("signature"))))
            .toList();

    java.net.http.HttpClient http = java.net.http.HttpClient.newHttpClient();
    String historicalUrl =
        resolverBaseUrl
            + "/v1/identities/"
            + issuerHex
            + "/states/"
            + issuanceHashHex;
    String currentUrl = resolverBaseUrl + "/v1/identities/" + issuerHex;

    Map<String, Object> historical = getJson(http, historicalUrl);
    Map<String, Object> current = getJson(http, currentUrl);

    byte[] canonicalState =
        Base64.getUrlDecoder().decode((String) historical.get("canonicalState"));
    IdentityState historicalState = OpenIdentityCborDecoder.decodeState(canonicalState);

    VerificationResult result =
        CredentialVerifier.verifyResult(
            credentialBytes,
            IdentityId.of(HEX.parseHex(issuerHex)),
            new StateHash(MultihashSha256.of(HEX.parseHex(issuanceHashHex))),
            historicalState,
            proofs);

    System.out.println("Credential issuer: " + issuerHex);
    System.out.println("Issuance StateHash: " + issuanceHashHex);
    System.out.println("Historical sequence: " + historical.get("sequence"));
    System.out.println("Current sequence: " + current.get("sequence"));
    System.out.println("Historical state version: " + historical.get("stateVersion"));
    System.out.println("Current state version: " + current.get("stateVersion"));
    System.out.println("Cryptographic verification: " + (result.valid() ? "VALID" : "INVALID"));
    if (!result.valid()) {
      System.out.println("Error: " + result.error());
      System.out.println("Detail: " + result.detail());
      throw new IllegalStateException("Credential verification failed");
    }
  }

  @SuppressWarnings("unchecked")
  private static Map<String, Object> getJson(
      java.net.http.HttpClient http, String url) throws Exception {
    java.net.http.HttpRequest request =
        java.net.http.HttpRequest.newBuilder(java.net.URI.create(url)).GET().build();
    java.net.http.HttpResponse<String> response =
        http.send(request, java.net.http.HttpResponse.BodyHandlers.ofString());
    if (response.statusCode() != 200) {
      throw new IllegalStateException(
          "Resolver returned HTTP " + response.statusCode() + " for " + url);
    }
    return JSON.readValue(response.body(), Map.class);
  }

  private static void rotateAssertion(String currentStateHashHex) throws Exception {
    DevWallet wallet = load();
    if (wallet.assertion() == null) {
      throw new IllegalStateException("No active assertion key exists.");
    }
    if (wallet.pendingAssertion() != null) {
      throw new IllegalStateException(
          "A pending assertion key already exists. Submit/activate or discard it first.");
    }

    DevWallet.KeyEntry controller = activeController(wallet);
    int assertionNumber =
        wallet.assertion().name().startsWith("assertion-")
            ? Integer.parseInt(wallet.assertion().name().substring("assertion-".length())) + 1
            : 2;
    DevWallet.KeyEntry nextAssertion =
        newKey("assertion-" + assertionNumber, new SecureRandom());

    VerificationMethod controllerMethod = verificationMethod(controller);
    VerificationMethod assertionMethod = verificationMethod(nextAssertion);
    SetAssertionPolicyOperation operation =
        new SetAssertionPolicyOperation(
            IdentityId.of(HEX.parseHex(wallet.identityHex())),
            Sequence.of(4),
            new StateHash(MultihashSha256.of(HEX.parseHex(currentStateHashHex))),
            AssertionPolicy.single(assertionMethod));

    SignatureProof authorization =
        sign(
            controller,
            controllerMethod.id(),
            SigningInputs.operation(operation.encode()));
    SignatureProof possession =
        sign(
            nextAssertion,
            assertionMethod.id(),
            SigningInputs.controllerProof(operation.encode(), assertionMethod.id()));

    save(
        new DevWallet(
            wallet.identityHex(),
            wallet.activeController(),
            wallet.pendingController(),
            wallet.controllers(),
            wallet.assertion(),
            nextAssertion));

    Map<String, Object> request =
        Map.of(
            "operation",
            b64url(operation.encode()),
            "proofs",
            List.of(proofJson(authorization)),
            "proofsOfPossession",
            List.of(proofJson(possession)));

    System.out.println("Identity: " + wallet.identityHex());
    System.out.println("Current assertion key: " + wallet.assertion().name());
    System.out.println("Pending assertion key: " + nextAssertion.name());
    System.out.println(JSON.writeValueAsString(request));
  }

  private static void issueCredential(String issuanceStateHashHex) throws Exception {
    DevWallet wallet = load();
    if (wallet.assertion() == null) {
      throw new IllegalStateException("No active assertion key. Activate assertion authority first.");
    }

    byte[] credentialId = new byte[32];
    new SecureRandom().nextBytes(credentialId);
    byte[] subject = ("did:open-dev:" + wallet.identityHex()).getBytes(java.nio.charset.StandardCharsets.UTF_8);
    long validFrom = java.time.Instant.now().getEpochSecond();
    OpenIdentityCredential credential =
        new OpenIdentityCredential(
            credentialId,
            IdentityId.of(HEX.parseHex(wallet.identityHex())),
            new StateHash(MultihashSha256.of(HEX.parseHex(issuanceStateHashHex))),
            validFrom,
            validFrom + 86400,
            "https://openidentity.org/credentials/basic/v1",
            subject,
            Map.of(
                "name", "OpenIdentity Resolver Development Credential",
                "purpose", "historical-state interoperability"));

    VerificationMethod assertionMethod = verificationMethod(wallet.assertion());
    byte[] credentialBytes = credential.encode();
    SignatureProof proof =
        sign(
            wallet.assertion(),
            assertionMethod.id(),
            CredentialSigningInputs.credential(credentialBytes));

    Map<String, Object> output =
        Map.of(
            "credential", b64url(credentialBytes),
            "issuer", wallet.identityHex(),
            "issuanceStateHash", issuanceStateHashHex,
            "proofs", List.of(proofJson(proof)));

    Path credentialFile = WALLET.getParent().resolve("credential-1.json");
    JSON.writeValue(credentialFile.toFile(), output);
    System.out.println("Issued credential: " + credentialFile);
    System.out.println("Issuer: " + wallet.identityHex());
    System.out.println("Issuance StateHash: " + issuanceStateHashHex);
    System.out.println("Credential ID: " + HEX.formatHex(credentialId));
  }

  private static Map<String, Object> proofJson(SignatureProof proof) {
    return Map.of(
        "methodId", b64url(proof.methodId().bytes()),
        "signature", b64url(proof.signature()));
  }

  private static void save(DevWallet wallet) throws Exception {
    JSON.writeValue(WALLET.toFile(), wallet);
  }

  static DevWallet load() throws Exception {
    if (!Files.exists(WALLET)) {
      throw new IllegalStateException("Wallet not found. Run init first.");
    }
    return JSON.readValue(WALLET.toFile(), DevWallet.class);
  }

  static VerificationMethod verificationMethod(DevWallet.KeyEntry entry) {
    return new VerificationMethod(
        VerificationMethodId.of(HEX.parseHex(entry.methodIdHex())),
        Ed25519Key.of(HEX.parseHex(entry.publicKeyHex())));
  }

  static SignatureProof sign(
      DevWallet.KeyEntry entry, VerificationMethodId methodId, byte[] input) throws Exception {
    KeyFactory factory = KeyFactory.getInstance("Ed25519");
    PrivateKey privateKey =
        factory.generatePrivate(
            new java.security.spec.PKCS8EncodedKeySpec(
                Base64.getDecoder().decode(entry.privateKeyPkcs8Base64())));
    Signature signer = Signature.getInstance("Ed25519");
    signer.initSign(privateKey);
    signer.update(input);
    return new SignatureProof(methodId, signer.sign());
  }

  static DevWallet.KeyEntry newKey(String name, SecureRandom random) throws Exception {
    byte[] methodId = new byte[VerificationMethodId.LENGTH];
    random.nextBytes(methodId);
    KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    byte[] raw = rawEd25519((EdECPublicKey) pair.getPublic());
    return new DevWallet.KeyEntry(
        name,
        HEX.formatHex(methodId),
        HEX.formatHex(raw),
        Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()),
        Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
  }

  private static DevWallet.KeyEntry activeController(DevWallet wallet) {
    return wallet.controllers().stream()
        .filter(k -> k.name().equals(wallet.activeController()))
        .findFirst()
        .orElseThrow(() -> new IllegalStateException("Active controller missing from wallet"));
  }

  private static byte[] rawEd25519(EdECPublicKey publicKey) {
    EdECPoint point = publicKey.getPoint();
    byte[] y = point.getY().toByteArray();
    byte[] encoded = new byte[32];
    for (int i = 0; i < Math.min(y.length, 32); i++) {
      encoded[i] = y[y.length - 1 - i];
    }
    if (point.isXOdd()) encoded[31] |= (byte) 0x80;
    return encoded;
  }

  private static String b64url(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private static void usage() {
    throw new IllegalArgumentException("Usage: DevWalletCli <init|create|rotate STATE_HASH_HEX|activate-controller|set-assertion-policy STATE_HASH_HEX|activate-assertion|discard-pending-assertion|issue-credential STATE_HASH_HEX|rotate-assertion STATE_HASH_HEX|verify-credential [RESOLVER_URL]>");
  }
}
