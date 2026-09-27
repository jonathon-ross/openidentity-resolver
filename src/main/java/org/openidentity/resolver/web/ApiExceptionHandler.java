package org.openidentity.resolver.web;

import java.time.Instant;
import java.util.Map;
import org.openidentity.resolver.operation.OperationSubmissionException;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestControllerAdvice
final class ApiExceptionHandler {
  @ExceptionHandler(OperationSubmissionException.class)
  ResponseEntity<Map<String, Object>> invalidOperation(OperationSubmissionException e) {
    HttpStatus status =
        "IDENTITY_ALREADY_EXISTS".equals(e.code()) ? HttpStatus.CONFLICT : HttpStatus.BAD_REQUEST;
    return ResponseEntity.status(status)
        .body(
            Map.of(
                "timestamp", Instant.now().toString(),
                "status", status.value(),
                "error", e.code(),
                "message", e.getMessage() == null ? e.code() : e.getMessage()));
  }

  @ExceptionHandler(InvalidResolutionIdentifierException.class)
  ResponseEntity<Map<String, Object>> invalidIdentifier(InvalidResolutionIdentifierException e) {
    return ResponseEntity.badRequest()
        .body(
            Map.of(
                "timestamp",
                Instant.now().toString(),
                "status",
                400,
                "error",
                "INVALID_RESOLUTION_IDENTIFIER",
                "message",
                e.getMessage()));
  }
}
