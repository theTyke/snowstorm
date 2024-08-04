package org.snomed.snowstorm.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.PrePersist;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "api_key")
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ApiKey {

    @Id
    private UUID id;

    @Column(nullable = false, unique = true)
    private String hashedSecret;

    @Column
    private Instant expiresAt;

    @PrePersist
    public void prePersist() {
        id = UUID.randomUUID();
    }

}
