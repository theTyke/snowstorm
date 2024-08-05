package org.snomed.snowstorm.auth.repository;

import org.snomed.snowstorm.auth.entity.ApiKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface ApiKeyRepository extends JpaRepository<ApiKey, UUID> {

    Optional<ApiKey> findByHashedSecret(String hashedSecret);

    Optional<ApiKey> findByApplication(String application);

}
