package org.snomed.snowstorm.auth.service.impl;

import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.digest.DigestUtils;
import org.snomed.snowstorm.auth.config.AuthConfig;
import org.snomed.snowstorm.auth.entity.ApiKey;
import org.snomed.snowstorm.auth.repository.ApiKeyRepository;
import org.snomed.snowstorm.auth.service.ApiKeyService;
import org.snomed.snowstorm.auth.util.ApiKeyUtil;
import org.snomed.snowstorm.auth.util.SignedApiKey;
import org.snomed.snowstorm.rest.pojo.ApiKeyDto;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.time.OffsetDateTime;
import java.util.Optional;

@RequiredArgsConstructor
@Service
public class ApiKeyServiceImpl implements ApiKeyService {

    private final ApiKeyRepository apiKeyRepository;
    private final AuthConfig authConfig;

    @Override
    public ApiKeyDto createApiKey(final String application, final OffsetDateTime expiresAt) {
        final Optional<ApiKey> apiKeyOpt = apiKeyRepository.findByApplication(application);

        apiKeyOpt.ifPresent(alreadyExists -> {
            throw new ResponseStatusException(HttpStatus.CONFLICT);
        });

        try {
            final SignedApiKey signedApiKey = ApiKeyUtil.generateSignedApiKey(authConfig.getApiKeyPrefix(), authConfig.getPrivateKey());

            final ApiKey apiKey = new ApiKey();

            apiKey.setApplication(application);
            apiKey.setHashedSecret(DigestUtils.sha512Hex(signedApiKey.secret()));
            apiKey.setExpiresAt(expiresAt.toInstant());

            return new ApiKeyDto(application, signedApiKey.toString(), expiresAt);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @Override
    public void deleteApiKey(final String application) {
        final Optional<ApiKey> apiKeyOpt = apiKeyRepository.findByApplication(application);

        apiKeyOpt.ifPresentOrElse(
                apiKeyRepository::delete,
                () -> {
                    throw new ResponseStatusException(HttpStatus.NOT_FOUND);
                });
    }

}
