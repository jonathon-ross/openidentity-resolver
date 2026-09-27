package org.openidentity.resolver.operation;

/** Structured resolver rejection carrying a stable protocol/API error code. */
public final class OperationSubmissionException extends RuntimeException {
  /** Stable machine-readable resolver error code. */
  private final String code;

  /**
   * Creates a structured operation rejection.
   *
   * @param code stable machine-readable error code
   * @param message human-readable diagnostic
   */
  public OperationSubmissionException(String code, String message) {
    super(message);
    this.code = code;
  }

  /**\n   * Returns the stable machine-readable error code.\n   *\n   * @return resolver error code\n   */
  public String code() {
    return code;
  }
}
