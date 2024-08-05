package org.snomed.snowstorm.rest.pojo;

import jakarta.annotation.Nullable;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.OffsetDateTime;

@Data
@AllArgsConstructor
public class ApiKeyDto {
    @NotNull
    private String application;
    @NotNull
    private String apiKey;
    @Nullable
    private OffsetDateTime expiresAt;
}
