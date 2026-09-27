package org.openidentity.resolver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Spring Boot entry point for the OpenIdentity resolver HTTP service. */
@SpringBootApplication
public class OpenIdentityResolverApplication {
  /** Creates the application bootstrap component. */
  public OpenIdentityResolverApplication() {}

  /**
   * Starts the resolver service.
   *
   * @param args Spring Boot command-line arguments
   */
  public static void main(String[] args) {
    SpringApplication.run(OpenIdentityResolverApplication.class, args);
  }
}
