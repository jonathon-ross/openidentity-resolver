package org.openidentity.resolver.tools;

import java.util.List;

/** Local-only development wallet representation. Never commit generated wallet files. */
public record DevWallet(
    String identityHex,
    String activeController,
    String pendingController,
    List<KeyEntry> controllers,
    KeyEntry assertion,
    KeyEntry pendingAssertion) {

  public record KeyEntry(
      String name,
      String methodIdHex,
      String publicKeyHex,
      String publicKeyX509Base64,
      String privateKeyPkcs8Base64) {}
}
