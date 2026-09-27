package org.openidentity.resolver.web;

import org.openidentity.resolver.state.IdentityStateRepository;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/** HTTP endpoints for current and exact historical identity-state resolution. */
@RestController
@RequestMapping("/v1/identities")
public final class ResolutionController {
  private final IdentityStateRepository states;

  /**
   * @param states immutable identity-state repository
   */
  public ResolutionController(IdentityStateRepository states) {
    this.states = states;
  }

  /**
   * Resolves the highest-sequence state for an identity.
   *
   * @param identity hexadecimal 32-byte IdentityId
   * @return current state or HTTP 404
   */
  @GetMapping("/{identity}")
  public ResponseEntity<ResolutionResponse> current(@PathVariable String identity) {
    byte[] id = Hex.identity(identity);
    return states
        .findCurrent(id)
        .map(ResolutionResponse::from)
        .map(ResponseEntity::ok)
        .orElseGet(() -> ResponseEntity.notFound().build());
  }

  /**
   * Resolves an exact historical identity/state-hash pair.
   *
   * @param identity hexadecimal 32-byte IdentityId
   * @param stateHash hexadecimal 34-byte StateHash Multihash
   * @return exact historical state or HTTP 404
   */
  @GetMapping("/{identity}/states/{stateHash}")
  public ResponseEntity<ResolutionResponse> historical(
      @PathVariable String identity, @PathVariable String stateHash) {
    byte[] id = Hex.identity(identity);
    byte[] hash = Hex.stateHash(stateHash);
    return states
        .findHistorical(id, hash)
        .map(ResolutionResponse::from)
        .map(ResponseEntity::ok)
        .orElseGet(() -> ResponseEntity.notFound().build());
  }
}
