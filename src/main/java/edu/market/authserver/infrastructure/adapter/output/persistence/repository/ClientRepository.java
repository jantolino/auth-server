package edu.market.authserver.infrastructure.adapter.output.persistence.repository;

import edu.market.authserver.infrastructure.adapter.output.persistence.entity.ClientEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

/**
 * Repositorio JPA para la entidad ClientEntity. Proporciona operaciones CRUD básicas y consultas
 * personalizadas.
 */
@Repository
public interface ClientRepository extends JpaRepository<ClientEntity, String> {

  /**
   * Busca un cliente por su ID de cliente.
   *
   * @param clientId ID del cliente
   * @return Optional con el cliente si existe, vacío en caso contrario
   */
  Optional<ClientEntity> findByClientId(String clientId);
}
