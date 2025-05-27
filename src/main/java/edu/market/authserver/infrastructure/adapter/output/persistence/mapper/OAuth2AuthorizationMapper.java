package edu.market.authserver.infrastructure.adapter.output.persistence.mapper;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.jsontype.BasicPolymorphicTypeValidator;
import com.fasterxml.jackson.databind.jsontype.PolymorphicTypeValidator;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import edu.market.authserver.infrastructure.adapter.output.persistence.JpaOAuth2AuthorizationService;
import edu.market.authserver.infrastructure.adapter.output.persistence.entity.AuthorizationEntity;
import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/** Mapper para convertir entre OAuth2Authorization y AuthorizationEntity. */
@Slf4j
@Component
public class OAuth2AuthorizationMapper {

  private final ObjectMapper objectMapper;

  public OAuth2AuthorizationMapper(ObjectMapper objectMapper) {

    ClassLoader classLoader = JpaOAuth2AuthorizationService.class.getClassLoader();
    List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);    

    this.objectMapper = new ObjectMapper();
    this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
    this.objectMapper.registerModule(new JavaTimeModule());
    this.objectMapper.registerModules(securityModules);
  }

  /**
   * Convierte un OAuth2Authorization a una entidad AuthorizationEntity.
   *
   * @param authorization La autorización OAuth2
   * @return La entidad AuthorizationEntity
   */
  public AuthorizationEntity toEntity(OAuth2Authorization authorization) {

    AuthorizationEntity entity = new AuthorizationEntity();

    entity.setId(authorization.getId());
    entity.setRegisteredClientId(authorization.getRegisteredClientId());
    entity.setPrincipalName(authorization.getPrincipalName());
    entity.setAuthorizationGrantType(authorization.getAuthorizationGrantType().getValue());
    entity.setAuthorizedScopes(
        StringUtils.collectionToDelimitedString(authorization.getAuthorizedScopes(), ","));
    entity.setAttributes(writeMap(authorization.getAttributes()));
    entity.setState(authorization.getAttribute(OAuth2ParameterNames.STATE));

    OAuth2Authorization.Token<OAuth2AuthorizationCode> authorizationCode =
        authorization.getToken(OAuth2AuthorizationCode.class);
    setTokenValues(
        authorizationCode,
        entity::setAuthorizationCodeValue,
        entity::setAuthorizationCodeIssuedAt,
        entity::setAuthorizationCodeExpiresAt,
        entity::setAuthorizationCodeMetadata);

    OAuth2Authorization.Token<OAuth2AccessToken> accessToken =
        authorization.getToken(OAuth2AccessToken.class);
    setTokenValues(
        accessToken,
        entity::setAccessTokenValue,
        entity::setAccessTokenIssuedAt,
        entity::setAccessTokenExpiresAt,
        entity::setAccessTokenMetadata);
    if (accessToken != null && accessToken.getToken().getScopes() != null) {
      entity.setAccessTokenScopes(
          StringUtils.collectionToDelimitedString(accessToken.getToken().getScopes(), ","));
    }

    OAuth2Authorization.Token<OAuth2RefreshToken> refreshToken =
        authorization.getToken(OAuth2RefreshToken.class);
    setTokenValues(
        refreshToken,
        entity::setRefreshTokenValue,
        entity::setRefreshTokenIssuedAt,
        entity::setRefreshTokenExpiresAt,
        entity::setRefreshTokenMetadata);

    OAuth2Authorization.Token<OidcIdToken> oidcIdToken = authorization.getToken(OidcIdToken.class);
    setTokenValues(
        oidcIdToken,
        entity::setOidcIdTokenValue,
        entity::setOidcIdTokenIssuedAt,
        entity::setOidcIdTokenExpiresAt,
        entity::setOidcIdTokenMetadata);
    if (oidcIdToken != null) {
      entity.setOidcIdTokenClaims(writeMap(oidcIdToken.getClaims()));
    }

    OAuth2Authorization.Token<OAuth2UserCode> userCode =
        authorization.getToken(OAuth2UserCode.class);
    setTokenValues(
        userCode,
        entity::setUserCodeValue,
        entity::setUserCodeIssuedAt,
        entity::setUserCodeExpiresAt,
        entity::setUserCodeMetadata);

    OAuth2Authorization.Token<OAuth2DeviceCode> deviceCode =
        authorization.getToken(OAuth2DeviceCode.class);
    setTokenValues(
        deviceCode,
        entity::setDeviceCodeValue,
        entity::setDeviceCodeIssuedAt,
        entity::setDeviceCodeExpiresAt,
        entity::setDeviceCodeMetadata);

    return entity;
  }

  /**
   * Convierte una entidad AuthorizationEntity a un OAuth2Authorization.
   *
   * @param entity La entidad AuthorizationEntity
   * @return La autorización OAuth2
   */
  public OAuth2Authorization toObject(
      AuthorizationEntity entity, RegisteredClient registeredClient) {

    if (registeredClient == null) {
      throw new DataRetrievalFailureException(
          "The RegisteredClient with id '"
              + entity.getRegisteredClientId()
              + "' was not found in the RegisteredClientRepository.");
    }

    OAuth2Authorization.Builder builder =
        OAuth2Authorization.withRegisteredClient(registeredClient)
            .id(entity.getId())
            .principalName(entity.getPrincipalName())
            .authorizationGrantType(
                resolveAuthorizationGrantType(entity.getAuthorizationGrantType()))
            .authorizedScopes(StringUtils.commaDelimitedListToSet(entity.getAuthorizedScopes()))
            .attributes(attributes -> attributes.putAll(parseMap(entity.getAttributes())));
    if (entity.getState() != null) {
      builder.attribute(OAuth2ParameterNames.STATE, entity.getState());
    }

    if (entity.getAuthorizationCodeValue() != null) {
      OAuth2AuthorizationCode authorizationCode =
          new OAuth2AuthorizationCode(
              entity.getAuthorizationCodeValue(),
              entity.getAuthorizationCodeIssuedAt(),
              entity.getAuthorizationCodeExpiresAt());
      builder.token(
          authorizationCode,
          metadata -> metadata.putAll(parseMap(entity.getAuthorizationCodeMetadata())));
    }

    if (entity.getAccessTokenValue() != null) {
      OAuth2AccessToken accessToken =
          new OAuth2AccessToken(
              OAuth2AccessToken.TokenType.BEARER,
              entity.getAccessTokenValue(),
              entity.getAccessTokenIssuedAt(),
              entity.getAccessTokenExpiresAt(),
              StringUtils.commaDelimitedListToSet(entity.getAccessTokenScopes()));
      builder.token(
          accessToken, metadata -> metadata.putAll(parseMap(entity.getAccessTokenMetadata())));
    }

    if (entity.getRefreshTokenValue() != null) {
      OAuth2RefreshToken refreshToken =
          new OAuth2RefreshToken(
              entity.getRefreshTokenValue(),
              entity.getRefreshTokenIssuedAt(),
              entity.getRefreshTokenExpiresAt());
      builder.token(
          refreshToken, metadata -> metadata.putAll(parseMap(entity.getRefreshTokenMetadata())));
    }

    if (entity.getOidcIdTokenValue() != null) {
      OidcIdToken idToken =
          new OidcIdToken(
              entity.getOidcIdTokenValue(),
              entity.getOidcIdTokenIssuedAt(),
              entity.getOidcIdTokenExpiresAt(),
              parseMap(entity.getOidcIdTokenClaims()));
      builder.token(
          idToken, metadata -> metadata.putAll(parseMap(entity.getOidcIdTokenMetadata())));
    }

    if (entity.getUserCodeValue() != null) {
      OAuth2UserCode userCode =
          new OAuth2UserCode(
              entity.getUserCodeValue(),
              entity.getUserCodeIssuedAt(),
              entity.getUserCodeExpiresAt());
      builder.token(userCode, metadata -> metadata.putAll(parseMap(entity.getUserCodeMetadata())));
    }

    if (entity.getDeviceCodeValue() != null) {
      OAuth2DeviceCode deviceCode =
          new OAuth2DeviceCode(
              entity.getDeviceCodeValue(),
              entity.getDeviceCodeIssuedAt(),
              entity.getDeviceCodeExpiresAt());
      builder.token(
          deviceCode, metadata -> metadata.putAll(parseMap(entity.getDeviceCodeMetadata())));
    }

    return builder.build();
  }

  private Map<String, Object> parseMap(String data) {
    try {
      return this.objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {});
    } catch (Exception ex) {
      throw new IllegalArgumentException(ex.getMessage(), ex);
    }
  }

  private String writeMap(Map<String, Object> metadata) {
    
    try {
      return this.objectMapper.writeValueAsString(metadata);
    } catch (Exception ex) {
      throw new IllegalArgumentException(ex.getMessage(), ex);
    }
  }

  private void setTokenValues(OAuth2Authorization.Token<?> token, Consumer<String> tokenValueConsumer,
      Consumer<Instant> issuedAtConsumer, Consumer<Instant> expiresAtConsumer, Consumer<String> metadataConsumer) {

    if (token != null) {
      OAuth2Token oAuth2Token = token.getToken();
      tokenValueConsumer.accept(oAuth2Token.getTokenValue());
      issuedAtConsumer.accept(oAuth2Token.getIssuedAt());
      expiresAtConsumer.accept(oAuth2Token.getExpiresAt());
      metadataConsumer.accept(writeMap(token.getMetadata()));
    }
  }

  private AuthorizationGrantType resolveAuthorizationGrantType(String authorizationGrantType) {
    if (AuthorizationGrantType.AUTHORIZATION_CODE.getValue().equals(authorizationGrantType)) {
      return AuthorizationGrantType.AUTHORIZATION_CODE;
    } else if (AuthorizationGrantType.CLIENT_CREDENTIALS
        .getValue()
        .equals(authorizationGrantType)) {
      return AuthorizationGrantType.CLIENT_CREDENTIALS;
    } else if (AuthorizationGrantType.REFRESH_TOKEN.getValue().equals(authorizationGrantType)) {
      return AuthorizationGrantType.REFRESH_TOKEN;
    } else if (AuthorizationGrantType.DEVICE_CODE.getValue().equals(authorizationGrantType)) {
      return AuthorizationGrantType.DEVICE_CODE;
    }
    return new AuthorizationGrantType(authorizationGrantType);
  }  
}


