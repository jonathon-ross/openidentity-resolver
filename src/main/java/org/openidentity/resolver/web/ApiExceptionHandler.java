package org.openidentity.resolver.web;

import java.time.Instant;
import java.util.Map;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestControllerAdvice
final class ApiExceptionHandler {
  @ExceptionHandler(InvalidResolutionIdentifierException.class)
  ResponseEntity<Map<String, Object>> invalidIdentifier(InvalidResolutionIdentifierException e) {
    return ResponseEntity.badRequest().body(Map.of(
        "timestamp", Instant.now().toString(),
        "status", 400,
        "error", "INVALID_RESOLUTION_IDENTIFIER",
        "message", e.getMessage()));
  }
}
