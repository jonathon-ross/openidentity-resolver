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
import org.openidentity.operations.CreateOperation;

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
    if (args.length != 1) usage();
    switch (args[0]) {
      case "init" -> init();
      case "create" -> create();
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
        new DevWallet(HEX.formatHex(identity), controller.name(), List.of(controller), null);
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
    throw new IllegalArgumentException("Usage: DevWalletCli <init|create>");
  }
}
