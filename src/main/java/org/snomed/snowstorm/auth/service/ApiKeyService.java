package org.snomed.snowstorm.auth.service;

import org.snomed.snowstorm.rest.pojo.ApiKeyDto;

import java.time.OffsetDateTime;

public interface ApiKeyService {

    ApiKeyDto createApiKey(final String application, final OffsetDateTime expiresAt);

    void deleteApiKey(final String application);
}
