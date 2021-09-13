package com.sivanagireddy.authserver.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@EnableWebSecurity
@Order(3)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

  @Value("${app.user.username}")
  private String username;

  @Value("${app.user.password}")
  private String password;

  private final PasswordEncoder passwordEncoder;

  public WebSecurityConfig(
      PasswordEncoder passwordEncoder) {
    this.passwordEncoder = passwordEncoder;
  }

  @Bean
  public UserDetailsService userDetailsService() {
    return new InMemoryUserDetailsManager(
        User.withUsername(username)
            .password(passwordEncoder.encode(password))
            .roles("USER")
            .build()
    );
  }
}
