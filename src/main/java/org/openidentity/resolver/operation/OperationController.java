package org.openidentity.resolver.operation;

import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/operations")
public class OperationController {
  private final OperationSubmissionService submissions;

  public OperationController(OperationSubmissionService submissions) {
    this.submissions = submissions;
  }

  @PostMapping
  public ResponseEntity<OperationSubmissionResponse> submit(
      @RequestBody OperationSubmissionRequest request) {
    return ResponseEntity.status(HttpStatus.CREATED).body(submissions.submit(request));
  }
}
