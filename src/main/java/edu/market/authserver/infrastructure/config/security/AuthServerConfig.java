package edu.market.authserver.infrastructure.config.security;

import java.time.Duration;
import java.time.Instant;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer.FrameOptionsConfig;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Configuración del servidor de autorización OAuth2. Define los filtros de seguridad, clientes
 * registrados y configuración del servidor.
 */
@Slf4j
@Configuration
@EnableWebSecurity
public class AuthServerConfig {

  @Bean
  @Order(1)
  public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
      throws Exception {

    OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
        OAuth2AuthorizationServerConfigurer.authorizationServer();

    http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
        .with(
            authorizationServerConfigurer,
            (authorizationServer) ->
                authorizationServer.oidc(
                    (oidc) ->
                        oidc.clientRegistrationEndpoint(
                            (clientRegistrationEndpoint) ->
                                clientRegistrationEndpoint.authenticationProviders(
                                    CustomClientMetadataConfig
                                        .configureCustomClientMetadataConverters()))))
        .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated());

    http.oauth2ResourceServer((resourceServer) -> resourceServer.jwt(Customizer.withDefaults()));

    return http.build();
  }

  @Bean
  @Order(2)
  public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
    http.headers(headers -> headers.frameOptions(FrameOptionsConfig::sameOrigin))
        .csrf(csrf -> csrf.ignoringRequestMatchers("/h2-console/**"))
        .authorizeHttpRequests(
            authorize ->
                authorize
                    .requestMatchers(
                        "/actuator/**",
                        "/error",
                        "/assets/**",
                        "/h2-console/**",
                        "/oauth2/**",
                        "/login",
                        "/login/**",
                        "/connect/**")
                    .permitAll()
                    .anyRequest()
                    .authenticated())
        .formLogin(Customizer.withDefaults());

    return http.build();
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder().build();
  }

  /** Clase encargada de hacer una carga inicial en la base de datos */
  @Bean
  public ApplicationRunner registerDefaultClient(
      RegisteredClientRepository registeredClientRepository) {
    return args -> {
      String clientId = "app-service";

      if (registeredClientRepository.findByClientId(clientId) == null) {
        log.info("Registering default client: {}", clientId);
        RegisteredClient registeredClient =
            RegisteredClient.withId("app-service")
                .clientId("app-service")
                .clientSecret(this.passwordEncoder().encode("app-service"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://localhost:9000/login/oauth2/code/oidc-client")
                .scope(OidcScopes.OPENID)
                .scope(OidcScopes.PROFILE)
                .scope(OidcScopes.EMAIL)
                .scope("read")
                .scope("write")
                .scope("client.read")
                .scope("client.create")
                .tokenSettings(
                    TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofHours(1))
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .authorizationCodeTimeToLive(Duration.ofMinutes(10))
                        .reuseRefreshTokens(true)
                        .build())
                .clientSettings(
                    ClientSettings.builder()
                        .requireAuthorizationConsent(true)
                        .requireProofKey(false)
                        .build())
                .clientIdIssuedAt(Instant.now())
                .build();
        registeredClientRepository.save(registeredClient);
        log.info("Default client registered successfully: {}", clientId);
      } else {
        log.info("Default client already exists: {}", clientId);
      }
    };
  }
}
