package org.openidentity.resolver.operation;

import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

/** HTTP endpoint for signed OpenIdentity operation submission. */
@RestController
@RequestMapping("/v1/operations")
public class OperationController {
  private final OperationSubmissionService submissions;

  /**
   * @param submissions verified operation application service
   */
  public OperationController(OperationSubmissionService submissions) {
    this.submissions = submissions;
  }

  /**
   * Verifies and applies one canonical protocol operation.
   *
   * @param request transport envelope containing operation bytes and detached proofs
   * @return resulting identity-state metadata with HTTP 201
   */
  @PostMapping
  public ResponseEntity<OperationSubmissionResponse> submit(
      @RequestBody OperationSubmissionRequest request) {
    return ResponseEntity.status(HttpStatus.CREATED).body(submissions.submit(request));
  }
}
