package com.sivanagireddy.authserver.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Map;
import org.springframework.security.oauth2.provider.endpoint.FrameworkEndpoint;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@FrameworkEndpoint
public class JwkSetEndpoint {

  private final KeyPair keyPair;

  public JwkSetEndpoint(KeyPair keyPair) {
    this.keyPair = keyPair;
  }

  @GetMapping("/.well-known/jwks.json")
  @ResponseBody
  public Map<String, Object> getKey() {
    RSAPublicKey rsaPublicKey = (RSAPublicKey) this.keyPair.getPublic();
    RSAKey rsaKey = new RSAKey.Builder(rsaPublicKey).build();
    return new JWKSet(rsaKey).toJSONObject();
  }
}
