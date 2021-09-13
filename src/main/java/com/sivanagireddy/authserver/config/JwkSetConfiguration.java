package com.sivanagireddy.authserver.config;

import java.security.KeyPair;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerEndpointsConfiguration;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Import(AuthorizationServerEndpointsConfiguration.class)
@Configuration
public class JwkSetConfiguration extends AuthorizationServerConfigurerAdapter {

  @Value("${app.oauth2.client-id}")
  private String clientId;

  @Value("${app.oauth2.client-secret}")
  private String clientSecret;

  private final AuthenticationManager authenticationManager;
  private final KeyPair keyPair;
  private final PasswordEncoder passwordEncoder;
  private final UserDetailsService userDetailsService;

  public JwkSetConfiguration(
      AuthenticationConfiguration authenticationConfiguration,
      KeyPair keyPair,
      PasswordEncoder passwordEncoder,
      UserDetailsService userDetailsService) throws Exception {
    this.authenticationManager = authenticationConfiguration.getAuthenticationManager();
    this.keyPair = keyPair;
    this.passwordEncoder = passwordEncoder;
    this.userDetailsService = userDetailsService;
  }

  @Override
  public void configure(AuthorizationServerSecurityConfigurer security) {
    security
        .tokenKeyAccess("permitAll()")
        .checkTokenAccess("isAuthenticated()")
        .allowFormAuthenticationForClients();
  }

  @Override
  public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
    clients
        .inMemory()
        .withClient(clientId)
        .secret(passwordEncoder.encode(clientSecret))
        .scopes("any")
        .autoApprove(true)
        .authorizedGrantTypes("refresh_token", "password");
  }

  @Override
  public void configure(AuthorizationServerEndpointsConfigurer endpoints) {
    endpoints.authenticationManager(this.authenticationManager)
        .accessTokenConverter(accessTokenConverter())
        .userDetailsService(userDetailsService)
        .tokenStore(endpoints.getTokenStore());
  }

  @Bean
  public TokenStore tokenStore() {
    return new JwtTokenStore(accessTokenConverter());
  }

  @Bean
  public JwtAccessTokenConverter accessTokenConverter() {
    JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
    accessTokenConverter.setKeyPair(this.keyPair);
    return accessTokenConverter;
  }
}
