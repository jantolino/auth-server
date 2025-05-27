package edu.market.authserver.infrastructure.adapter.output.persistence.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.Table;
import java.time.Instant;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Entidad JPA que representa un cliente OAuth2 registrado en la base de datos. Corresponde a la
 * tabla oauth2_registered_client.
 */
@Data
@Entity
@NoArgsConstructor
@Table(name = "oauth2_registered_client")
public class ClientEntity {

  @Id
  @Column(name = "id")
  private String id;

  @Column(name = "client_id", nullable = false)
  private String clientId;

  @Column(name = "client_id_issued_at", nullable = false)
  private Instant clientIdIssuedAt;

  @Column(name = "client_secret")
  private String clientSecret;

  @Column(name = "client_secret_expires_at")
  private Instant clientSecretExpiresAt;

  @Column(name = "client_name", nullable = false)
  private String clientName;

  @Column(name = "client_authentication_methods", nullable = false)
  private String clientAuthenticationMethods;

  @Column(name = "authorization_grant_types", nullable = false)
  private String authorizationGrantTypes;

  @Column(name = "redirect_uris")
  private String redirectUris;

  @Column(name = "post_logout_redirect_uris")
  private String postLogoutRedirectUris;

  @Column(name = "scopes", nullable = false)
  private String scopes;

  @Lob
  @Column(name = "client_settings", nullable = false)
  private String clientSettings;

  @Lob
  @Column(name = "token_settings", nullable = false)
  private String tokenSettings;
}
