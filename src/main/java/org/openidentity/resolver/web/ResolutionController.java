package org.openidentity.resolver.web;

import org.openidentity.resolver.state.IdentityStateRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/v1/identities")
public final class ResolutionController {
  private final IdentityStateRepository states;

  public ResolutionController(IdentityStateRepository states) {
    this.states = states;
  }

  @GetMapping("/{identity}")
  public ResponseEntity<ResolutionResponse> current(@PathVariable String identity) {
    byte[] id = Hex.identity(identity);
    return states.findCurrent(id)
        .map(ResolutionResponse::from)
        .map(ResponseEntity::ok)
        .orElseGet(() -> ResponseEntity.notFound().build());
  }

  @GetMapping("/{identity}/states/{stateHash}")
  public ResponseEntity<ResolutionResponse> historical(
      @PathVariable String identity, @PathVariable String stateHash) {
    byte[] id = Hex.identity(identity);
    byte[] hash = Hex.stateHash(stateHash);
    return states.findHistorical(id, hash)
        .map(ResolutionResponse::from)
        .map(ResponseEntity::ok)
        .orElseGet(() -> ResponseEntity.notFound().build());
  }
}
