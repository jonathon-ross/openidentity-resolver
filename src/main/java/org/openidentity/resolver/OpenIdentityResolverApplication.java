package org.openidentity.resolver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/** Starts the OpenIdentity resolver HTTP service. */
@SpringBootApplication
public class OpenIdentityResolverApplication {
  public static void main(String[] args) {
    SpringApplication.run(OpenIdentityResolverApplication.class, args);
  }
}
