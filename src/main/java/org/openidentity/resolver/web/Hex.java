package org.openidentity.resolver.web;

import java.util.HexFormat;

final class Hex {
  private static final HexFormat HEX = HexFormat.of();
  private Hex() {}

  static byte[] identity(String value) {
    return decodeExact(value, 32, "identity");
  }

  static byte[] stateHash(String value) {
    return decodeExact(value, 34, "stateHash");
  }

  static String encode(byte[] value) {
    return HEX.formatHex(value);
  }

  private static byte[] decodeExact(String value, int length, String field) {
    try {
      byte[] decoded = HEX.parseHex(value);
      if (decoded.length != length) throw new IllegalArgumentException();
      return decoded;
    } catch (IllegalArgumentException e) {
      throw new InvalidResolutionIdentifierException(field + " must be " + length + " bytes of hexadecimal");
    }
  }
}
