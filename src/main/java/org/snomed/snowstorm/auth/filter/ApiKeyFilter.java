package org.snomed.snowstorm.auth.filter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.digest.DigestUtils;
import org.snomed.snowstorm.auth.ApiKeyAuthenticationToken;
import org.snomed.snowstorm.auth.config.AuthConfig;
import org.snomed.snowstorm.auth.entity.ApiKey;
import org.snomed.snowstorm.auth.repository.ApiKeyRepository;
import org.snomed.snowstorm.auth.util.ApiKeyUtil;
import org.snomed.snowstorm.auth.util.SignedApiKey;
import org.springframework.http.HttpStatus;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.server.ResponseStatusException;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Collections;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class ApiKeyFilter extends OncePerRequestFilter {

    private final ApiKeyRepository apiKeyRepository;
    private final AuthConfig authConfig;

    @Override
    protected void doFilterInternal(final @NonNull HttpServletRequest request, final @NonNull HttpServletResponse response, final @NonNull FilterChain filterChain) throws ServletException, IOException {
        final Authentication existingAuthentication = SecurityContextHolder.getContext().getAuthentication();

        if (existingAuthentication != null && !(existingAuthentication instanceof AnonymousAuthenticationToken)) {
            filterChain.doFilter(request, response);
            return;
        }

        final Optional<String> signedApiKeyHeaderValueOpt = getApiKeyFromRequestHeaders(request, authConfig.getApiKeyHeader());

        if (signedApiKeyHeaderValueOpt.isEmpty()) {
            filterChain.doFilter(request, response);
            return;
        }

        final Optional<SignedApiKey> signedApiKeyOpt;
        try {
            signedApiKeyOpt = ApiKeyUtil.verifySignedApiKey(authConfig.getApiKeyPrefix(), authConfig.getPublicKey(), signedApiKeyHeaderValueOpt.get());
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Error while verifying API Key", e);
        }

        if (signedApiKeyOpt.isPresent()) {
            final SignedApiKey signedApiKey = signedApiKeyOpt.get();

            final Optional<ApiKey> applicationKeyOpt = apiKeyRepository.findByHashedSecret(DigestUtils.sha512Hex(signedApiKey.secret()));

            if (applicationKeyOpt.isPresent()) {
                final ApiKey applicationKey = applicationKeyOpt.get();
                final ApiKeyAuthenticationToken authenticationToken = new ApiKeyAuthenticationToken(applicationKey.getId(), Collections.emptySet(), applicationKey);
                authenticationToken.setAuthenticated(true);

                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }

        }

        filterChain.doFilter(request, response);
    }

    private static Optional<String> getApiKeyFromRequestHeaders(final HttpServletRequest request, final String apiKeyHeader) {
        final String signedApiKey = request.getHeader(apiKeyHeader);
        if (signedApiKey == null || signedApiKey.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(signedApiKey);
    }
}
