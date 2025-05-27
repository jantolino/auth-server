package edu.market.authserver.infrastructure.adapter.output.persistence;

import edu.market.authserver.infrastructure.adapter.output.persistence.entity.AuthorizationEntity;
import edu.market.authserver.infrastructure.adapter.output.persistence.entity.ClientEntity;
import edu.market.authserver.infrastructure.adapter.output.persistence.mapper.OAuth2AuthorizationMapper;
import edu.market.authserver.infrastructure.adapter.output.persistence.mapper.RegisteredClientMapper;
import edu.market.authserver.infrastructure.adapter.output.persistence.repository.AuthorizationRepository;
import edu.market.authserver.infrastructure.adapter.output.persistence.repository.ClientRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

/**
 * Implementación JPA del servicio de autorización OAuth2. Gestiona el almacenamiento y recuperación
 * de autorizaciones OAuth2.
 */
@Slf4j
@Component
public class JpaOAuth2AuthorizationService implements OAuth2AuthorizationService {

  private final AuthorizationRepository authorizationRepository;
  private final ClientRepository clientRepository;
  private final RegisteredClientMapper registeredClientMapper;
  private final OAuth2AuthorizationMapper authorizationMapper;

  public JpaOAuth2AuthorizationService(
      AuthorizationRepository authorizationRepository, ClientRepository clientRepository,
          OAuth2AuthorizationMapper oAuth2AuthorizationMapper, RegisteredClientMapper registeredClientMapper) {

    Assert.notNull(authorizationRepository, "authorizationRepository cannot be null");
    Assert.notNull(clientRepository, "clientRepository cannot be null");

    this.authorizationRepository = authorizationRepository;
    this.clientRepository = clientRepository;
    this.authorizationMapper = oAuth2AuthorizationMapper;
    this.registeredClientMapper = registeredClientMapper;
  }

  @Override
  public void save(OAuth2Authorization authorization) {
    Assert.notNull(authorization, "authorization cannot be null");
    log.info("Saving OAuth2 authorization: {}", authorization.getId());
    AuthorizationEntity entity = authorizationMapper.toEntity(authorization);
    authorizationRepository.save(entity);
  }

  @Override
  public void remove(OAuth2Authorization authorization) {
    Assert.notNull(authorization, "authorization cannot be null");
    log.info("Removing OAuth2 authorization: {}", authorization.getId());

    authorizationRepository.deleteById(authorization.getId());
  }

  @Override
  public OAuth2Authorization findById(String id) {
    Assert.hasText(id, "id cannot be empty");
    log.info("Finding OAuth2 authorization by id: {}", id);

    RegisteredClient registeredClient = null;
    AuthorizationEntity entity = authorizationRepository.findById(id).orElse(null);
    if (entity != null) {
      ClientEntity clientEntity =
          this.clientRepository.findByClientId(entity.getRegisteredClientId()).orElse(null);
      if (clientEntity != null) {
        registeredClient = this.registeredClientMapper.toObject(clientEntity);
      }
    }
    return this.authorizationMapper.toObject(entity, registeredClient);
  }

  @Override
  public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
    Assert.hasText(token, "token cannot be empty");
    log.info("Finding OAuth2 authorization by token: {}, tokenType: {}", token, tokenType);

    AuthorizationEntity entity = null;
    RegisteredClient registeredClient = null;

    if (tokenType == null) {
      // Buscar en todos los tipos de token
      entity =
          authorizationRepository
              .findByAccessTokenValue(token)
              .or(() -> authorizationRepository.findByRefreshTokenValue(token))
              .or(() -> authorizationRepository.findByAuthorizationCodeValue(token))
              .or(() -> authorizationRepository.findByDeviceCodeValue(token))
              .or(() -> authorizationRepository.findByUserCodeValue(token))
              .or(() -> authorizationRepository.findByState(token))
              .orElse(null);

    } else if (OAuth2ParameterNames.STATE.equals(tokenType.getValue())) {
      entity = authorizationRepository.findByState(token).orElse(null);
    } else if (OAuth2ParameterNames.CODE.equals(tokenType.getValue())) {
      entity = authorizationRepository.findByAuthorizationCodeValue(token).orElse(null);
    } else if (OAuth2ParameterNames.ACCESS_TOKEN.equals(tokenType.getValue())) {
      entity = authorizationRepository.findByAccessTokenValue(token).orElse(null);
    } else if (OAuth2ParameterNames.REFRESH_TOKEN.equals(tokenType.getValue())) {
      entity = authorizationRepository.findByRefreshTokenValue(token).orElse(null);
    } else if (AuthorizationGrantType.DEVICE_CODE.getValue().equals(tokenType.getValue())) {
      entity = authorizationRepository.findByDeviceCodeValue(token).orElse(null);
    } else {
      entity = authorizationRepository.findByUserCodeValue(token).orElse(null);
    }

    if (entity != null) {
      ClientEntity clientEntity = this.clientRepository.findById(entity.getRegisteredClientId()).orElse(null);
      if (clientEntity != null) {
        registeredClient = this.registeredClientMapper.toObject(clientEntity);
      }
    }
    return this.authorizationMapper.toObject(entity, registeredClient);
  }
}
