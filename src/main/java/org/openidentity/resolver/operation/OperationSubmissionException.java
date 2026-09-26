package org.openidentity.resolver.operation;

public final class OperationSubmissionException extends RuntimeException {
  private final String code;

  public OperationSubmissionException(String code, String message) {
    super(message);
    this.code = code;
  }

  public String code() {
    return code;
  }
}
