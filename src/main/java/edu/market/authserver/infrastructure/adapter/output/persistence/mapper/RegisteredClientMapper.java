package edu.market.authserver.infrastructure.adapter.output.persistence.mapper;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;

import edu.market.authserver.infrastructure.adapter.output.persistence.JpaRegisteredClientRepository;
import edu.market.authserver.infrastructure.adapter.output.persistence.entity.ClientEntity;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.jackson2.SecurityJackson2Modules;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.jackson2.OAuth2AuthorizationServerJackson2Module;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

/** Mapper para convertir entre RegisteredClient y ClientEntity. */
@Slf4j
@Component
public class RegisteredClientMapper {

  private final ObjectMapper objectMapper;

  public RegisteredClientMapper() {

    ClassLoader classLoader = JpaRegisteredClientRepository.class.getClassLoader();
    List<Module> securityModules = SecurityJackson2Modules.getModules(classLoader);
    
    this.objectMapper = new ObjectMapper();
    this.objectMapper.registerModules(securityModules);
    this.objectMapper.registerModule(new JavaTimeModule());
    this.objectMapper.registerModule(new OAuth2AuthorizationServerJackson2Module());
  }

  /**
   * Convierte un RegisteredClient a una entidad ClientEntity.
   *
   * @param registeredClient El cliente registrado
   * @return La entidad ClientEntity
   */
  public ClientEntity toEntity(RegisteredClient registeredClient) {
    try {
      List<String> clientAuthenticationMethods =
          new ArrayList<>(registeredClient.getClientAuthenticationMethods().size());
      registeredClient
          .getClientAuthenticationMethods()
          .forEach(
              clientAuthenticationMethod ->
                  clientAuthenticationMethods.add(clientAuthenticationMethod.getValue()));

      List<String> authorizationGrantTypes =
          new ArrayList<>(registeredClient.getAuthorizationGrantTypes().size());
      registeredClient
          .getAuthorizationGrantTypes()
          .forEach(
              authorizationGrantType ->
                  authorizationGrantTypes.add(authorizationGrantType.getValue()));

      ClientEntity entity = new ClientEntity();
      entity.setId(registeredClient.getId());
      entity.setClientId(registeredClient.getClientId());
      entity.setClientIdIssuedAt(registeredClient.getClientIdIssuedAt());
      entity.setClientSecret(registeredClient.getClientSecret());
      entity.setClientSecretExpiresAt(registeredClient.getClientSecretExpiresAt());
      entity.setClientName(registeredClient.getClientName());
      entity.setClientAuthenticationMethods(
          StringUtils.collectionToCommaDelimitedString(clientAuthenticationMethods));
      entity.setAuthorizationGrantTypes(
          StringUtils.collectionToCommaDelimitedString(authorizationGrantTypes));
      entity.setRedirectUris(
          StringUtils.collectionToCommaDelimitedString(registeredClient.getRedirectUris()));
      entity.setPostLogoutRedirectUris(
          StringUtils.collectionToCommaDelimitedString(
              registeredClient.getPostLogoutRedirectUris()));
      entity.setScopes(StringUtils.collectionToCommaDelimitedString(registeredClient.getScopes()));
      entity.setClientSettings(writeMap(registeredClient.getClientSettings().getSettings()));
      entity.setTokenSettings(writeMap(registeredClient.getTokenSettings().getSettings()));

      return entity;
    } catch (Exception ex) {
      throw new RuntimeException("Error converting RegisteredClient to ClientEntity", ex);
    }
  }

  /**
   * Convierte una entidad ClientEntity a un RegisteredClient.
   *
   * @param entity La entidad ClientEntity
   * @return El cliente registrado
   */
  public RegisteredClient toObject(ClientEntity entity) {
    try {

      Set<String> clientAuthenticationMethods =
          StringUtils.commaDelimitedListToSet(entity.getClientAuthenticationMethods());
      Set<String> authorizationGrantTypes =
          StringUtils.commaDelimitedListToSet(entity.getAuthorizationGrantTypes());
      Set<String> redirectUris = StringUtils.commaDelimitedListToSet(entity.getRedirectUris());
      Set<String> postLogoutRedirectUris =
          StringUtils.commaDelimitedListToSet(entity.getPostLogoutRedirectUris());
      Set<String> clientScopes = StringUtils.commaDelimitedListToSet(entity.getScopes());

      RegisteredClient.Builder builder =
          RegisteredClient.withId(entity.getId())
              .clientId(entity.getClientId())
              .clientIdIssuedAt(entity.getClientIdIssuedAt())
              .clientSecret(entity.getClientSecret())
              .clientSecretExpiresAt(entity.getClientSecretExpiresAt())
              .clientName(entity.getClientName())
              .redirectUris((uris) -> uris.addAll(redirectUris))
              .postLogoutRedirectUris((uris) -> uris.addAll(postLogoutRedirectUris))
              .scopes((scopes) -> scopes.addAll(clientScopes))

              .clientAuthenticationMethods(
                          authenticationMethods ->
                                  clientAuthenticationMethods.forEach(
                                          authenticationMethod ->
                                                  authenticationMethods.add(
                                                          new ClientAuthenticationMethod(authenticationMethod))))

              .authorizationGrantTypes(
                          (grantTypes) ->
                                  authorizationGrantTypes.forEach(
                                          grantType -> grantTypes.add(new AuthorizationGrantType(grantType))));


      Map<String, Object> clientSettingsMap = parseMap(entity.getClientSettings());
      builder.clientSettings(ClientSettings.withSettings(clientSettingsMap).build());

      Map<String, Object> tokenSettingsMap = parseMap(entity.getTokenSettings());
      builder.tokenSettings(TokenSettings.withSettings(tokenSettingsMap).build());

      return builder.build();
    } catch (Exception ex) {
      throw new RuntimeException("Error converting ClientEntity to RegisteredClient", ex);
    }
  }

  private Map<String, Object> parseMap(String data) {
    try {
      return this.objectMapper.readValue(data, new TypeReference<Map<String, Object>>() {});
    } catch (Exception ex) {
      throw new IllegalArgumentException(ex.getMessage(), ex);
    }
  }

  private String writeMap(Map<String, Object> data) {
    try {
      return this.objectMapper.writeValueAsString(data);
    } catch (Exception ex) {
      throw new IllegalArgumentException(ex.getMessage(), ex);
    }
  }
}
