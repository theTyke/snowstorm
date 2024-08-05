package org.snomed.snowstorm.rest.pojo;

import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotNull;
import lombok.Data;

import java.time.OffsetDateTime;

@Data
public class CreateApiKeyRequest {
    @NotNull
    private String application;
    @Nullable
    private OffsetDateTime expiresAt;
}
