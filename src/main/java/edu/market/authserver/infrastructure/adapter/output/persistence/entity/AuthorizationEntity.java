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
 * Entidad para almacenar las autorizaciones OAuth2. Basada en la documentación oficial de Spring
 * Authorization Server.
 */
@Data
@Entity
@NoArgsConstructor
@Table(name = "oauth2_authorization")
public class AuthorizationEntity {

  @Id
  @Column(name = "id", length = 100)
  private String id;

  @Column(name = "registered_client_id", length = 100, nullable = false)
  private String registeredClientId;

  @Column(name = "principal_name", length = 200, nullable = false)
  private String principalName;

  @Column(name = "authorization_grant_type", length = 100, nullable = false)
  private String authorizationGrantType;

  @Column(name = "authorized_scopes")
  private String authorizedScopes;

  @Lob
  @Column(name = "attributes")
  private String attributes;

  @Column(name = "state", length = 500)
  private String state;

  @Lob
  @Column(name = "authorization_code_value")
  private String authorizationCodeValue;

  @Column(name = "authorization_code_issued_at")
  private Instant authorizationCodeIssuedAt;

  @Column(name = "authorization_code_expires_at")
  private Instant authorizationCodeExpiresAt;

  @Column(name = "authorization_code_metadata")
  private String authorizationCodeMetadata;

  @Lob
  @Column(name = "access_token_value")
  private String accessTokenValue;

 @Column(name = "access_token_issued_at")
  private Instant accessTokenIssuedAt;

  @Column(name = "access_token_expires_at")
  private Instant accessTokenExpiresAt;

  @Column(name = "access_token_metadata")
  private String accessTokenMetadata;

  @Column(name = "access_token_type")
  private String accessTokenType;

  @Column(name = "access_token_scopes")
  private String accessTokenScopes;

  @Lob
  @Column(name = "refresh_token_value")
  private String refreshTokenValue;

  @Column(name = "refresh_token_issued_at")
  private Instant refreshTokenIssuedAt;

  @Column(name = "refresh_token_expires_at")
  private Instant refreshTokenExpiresAt;

  @Column(name = "refresh_token_metadata")
  private String refreshTokenMetadata;

  @Lob
  @Column(name = "oidc_id_token_value")
  private String oidcIdTokenValue;

  @Column(name = "oidc_id_token_issued_at")
  private Instant oidcIdTokenIssuedAt;

  @Column(name = "oidc_id_token_expires_at")
  private Instant oidcIdTokenExpiresAt;

  @Column(name = "oidc_id_token_metadata")
  private String oidcIdTokenMetadata;

  @Column(name = "oidc_id_token_claims")
  private String oidcIdTokenClaims;

  @Column(name = "user_code_value")
  private String userCodeValue;

  @Column(name = "user_code_issued_at")
  private Instant userCodeIssuedAt;

  @Column(name = "user_code_expires_at")
  private Instant userCodeExpiresAt;

  @Column(name = "user_code_metadata")
  private String userCodeMetadata;

  @Column(name = "device_code_value")
  private String deviceCodeValue;

  @Column(name = "device_code_issued_at")
  private Instant deviceCodeIssuedAt;

  @Column(name = "device_code_expires_at")
  private Instant deviceCodeExpiresAt;

  @Column(name = "device_code_metadata")
  private String deviceCodeMetadata;
}
