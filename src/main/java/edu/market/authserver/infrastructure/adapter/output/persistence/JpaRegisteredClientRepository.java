package edu.market.authserver.infrastructure.adapter.output.persistence;

import edu.market.authserver.infrastructure.adapter.output.persistence.entity.ClientEntity;
import edu.market.authserver.infrastructure.adapter.output.persistence.mapper.RegisteredClientMapper;
import edu.market.authserver.infrastructure.adapter.output.persistence.repository.ClientRepository;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

/**
 * Implementación de RegisteredClientRepository que utiliza JPA para persistir los clientes
 * registrados. Este adaptador utiliza el RegisteredClientMapper para convertir entre
 * RegisteredClient y ClientEntity.
 */
@Slf4j
@Component
public class JpaRegisteredClientRepository implements RegisteredClientRepository {

  private final ClientRepository clientRepository;
  private final RegisteredClientMapper registeredClientMapper;

  public JpaRegisteredClientRepository(ClientRepository clientRepository,
    RegisteredClientMapper registeredClientMapper) {

    Assert.notNull(clientRepository, "clientRepository cannot be null");
    this.clientRepository = clientRepository;
    this.registeredClientMapper = registeredClientMapper;
  }

  @Override
  public void save(RegisteredClient registeredClient) {
    log.info("Saving registered client: {}", registeredClient.getClientId());
    ClientEntity entity = this.registeredClientMapper.toEntity(registeredClient);
    this.clientRepository.save(entity);
  }

  @Override
  public RegisteredClient findById(String id) {
    log.info("Finding registered client by id: {}", id);
    return this.clientRepository
        .findById(id)
        .map(entity -> this.registeredClientMapper.toObject(entity))
        .orElse(null);
  }

  @Override
  public RegisteredClient findByClientId(String clientId) {
    log.info("Finding registered client by clientId: {}", clientId);
    return this.clientRepository
        .findByClientId(clientId)
        .map(entity -> this.registeredClientMapper.toObject(entity))
        .orElse(null);
  }
}
