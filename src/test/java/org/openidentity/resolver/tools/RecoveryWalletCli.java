package org.openidentity.resolver.tools;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.nio.file.*;
import java.security.*;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.*;
import java.util.*;
import org.openidentity.cbor.OpenIdentityCborEncoder;
import org.openidentity.core.*;
import org.openidentity.crypto.*;
import org.openidentity.operations.*;

/** Isolated local recovery lifecycle utility using a recovery-enabled development identity. */
public final class RecoveryWalletCli {
  private static final ObjectMapper JSON =
      new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
  private static final Path WALLET = Path.of(".openidentity", "recovery-wallet.json");
  private static final HexFormat HEX = HexFormat.of();

  private RecoveryWalletCli() {}

  public static void main(String[] args) throws Exception {
    if (args.length < 1) usage();
    switch (args[0]) {
      case "init" -> init();
      case "create" -> create();
      case "recover" -> {
        if (args.length != 2) usage();
        recover(args[1]);
      }
      default -> usage();
    }
  }

  private static void init() throws Exception {
    if (Files.exists(WALLET)) throw new IllegalStateException("Recovery wallet already exists");
    Files.createDirectories(WALLET.getParent());
    SecureRandom random = new SecureRandom();
    byte[] identity = new byte[32];
    random.nextBytes(identity);
    RecoveryWallet wallet =
        new RecoveryWallet(
            HEX.formatHex(identity),
            key("controller-1", random),
            key("recovery-1", random),
            null,
            null);
    JSON.writeValue(WALLET.toFile(), wallet);
    System.out.println("Created recovery wallet: " + WALLET);
    System.out.println("Identity: " + wallet.identityHex());
  }

  private static void create() throws Exception {
    RecoveryWallet wallet = load();
    VerificationMethod controller = method(wallet.controller());
    RecoveryPolicy recovery = RecoveryPolicy.single(method(wallet.recovery()));
    RecoveryCommitment commitment = commitment(recovery);
    CreateOperation operation =
        new CreateOperation(
            IdentityId.of(HEX.parseHex(wallet.identityHex())),
            ControllerPolicy.single(controller),
            commitment);
    SignatureProof auth =
        sign(wallet.controller(), controller.id(), SigningInputs.operation(operation.encode()));
    printRequest(operation.encode(), List.of(auth), List.of());
  }

  private static void recover(String currentStateHashHex) throws Exception {
    RecoveryWallet wallet = load();
    if (wallet.pendingController() != null || wallet.pendingRecovery() != null) {
      throw new IllegalStateException("Pending recovery already exists");
    }

    SecureRandom random = new SecureRandom();
    KeyEntry nextController = key("controller-2", random);
    KeyEntry nextRecovery = key("recovery-2", random);
    RecoveryPolicy currentRecovery = RecoveryPolicy.single(method(wallet.recovery()));
    RecoveryPolicy newRecovery = RecoveryPolicy.single(method(nextRecovery));

    RecoverOperation operation =
        new RecoverOperation(
            IdentityId.of(HEX.parseHex(wallet.identityHex())),
            Sequence.of(2),
            new StateHash(MultihashSha256.of(HEX.parseHex(currentStateHashHex))),
            ControllerPolicy.single(method(nextController)),
            currentRecovery,
            commitment(newRecovery));

    SignatureProof recoveryProof =
        sign(
            wallet.recovery(),
            method(wallet.recovery()).id(),
            SigningInputs.recovery(operation.encode(), method(wallet.recovery()).id()));
    SignatureProof controllerPop =
        sign(
            nextController,
            method(nextController).id(),
            SigningInputs.controllerProof(operation.encode(), method(nextController).id()));

    JSON.writeValue(
        WALLET.toFile(),
        new RecoveryWallet(
            wallet.identityHex(),
            wallet.controller(),
            wallet.recovery(),
            nextController,
            nextRecovery));

    printRequest(operation.encode(), List.of(recoveryProof), List.of(controllerPop));
  }

  private static RecoveryCommitment commitment(RecoveryPolicy policy) {
    return new RecoveryCommitment(
        MultihashSha256.digest(OpenIdentityCborEncoder.encodeRecoveryPolicy(policy)));
  }

  private static void printRequest(
      byte[] operation, List<SignatureProof> proofs, List<SignatureProof> pops) throws Exception {
    Map<String, Object> request =
        Map.of(
            "operation",
            b64(operation),
            "proofs",
            proofs.stream().map(RecoveryWalletCli::proof).toList(),
            "proofsOfPossession",
            pops.stream().map(RecoveryWalletCli::proof).toList());
    System.out.println(JSON.writeValueAsString(request));
  }

  private static Map<String, Object> proof(SignatureProof proof) {
    return Map.of(
        "methodId", b64(proof.methodId().bytes()),
        "signature", b64(proof.signature()));
  }

  private static SignatureProof sign(KeyEntry entry, VerificationMethodId id, byte[] input)
      throws Exception {
    PrivateKey key =
        KeyFactory.getInstance("Ed25519")
            .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(entry.privateKey())));
    Signature signer = Signature.getInstance("Ed25519");
    signer.initSign(key);
    signer.update(input);
    return new SignatureProof(id, signer.sign());
  }

  private static VerificationMethod method(KeyEntry entry) {
    return new VerificationMethod(
        VerificationMethodId.of(HEX.parseHex(entry.methodId())),
        Ed25519Key.of(HEX.parseHex(entry.publicKey())));
  }

  private static KeyEntry key(String name, SecureRandom random) throws Exception {
    byte[] id = new byte[16];
    random.nextBytes(id);
    KeyPair pair = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
    return new KeyEntry(
        name,
        HEX.formatHex(id),
        HEX.formatHex(raw((EdECPublicKey) pair.getPublic())),
        Base64.getEncoder().encodeToString(pair.getPrivate().getEncoded()));
  }

  private static byte[] raw(EdECPublicKey key) {
    EdECPoint point = key.getPoint();
    byte[] y = point.getY().toByteArray();
    byte[] out = new byte[32];
    for (int i = 0; i < Math.min(y.length, 32); i++) out[i] = y[y.length - 1 - i];
    if (point.isXOdd()) out[31] |= (byte) 0x80;
    return out;
  }

  private static RecoveryWallet load() throws Exception {
    return JSON.readValue(WALLET.toFile(), RecoveryWallet.class);
  }

  private static String b64(byte[] bytes) {
    return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
  }

  private static void usage() {
    throw new IllegalArgumentException("Usage: RecoveryWalletCli <init|create|recover STATE_HASH>");
  }

  public record RecoveryWallet(
      String identityHex,
      KeyEntry controller,
      KeyEntry recovery,
      KeyEntry pendingController,
      KeyEntry pendingRecovery) {}

  public record KeyEntry(String name, String methodId, String publicKey, String privateKey) {}
}
