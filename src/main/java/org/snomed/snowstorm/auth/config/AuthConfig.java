package org.snomed.snowstorm.auth.config;

import lombok.Getter;
import lombok.RequiredArgsConstructor;
import org.snomed.snowstorm.auth.util.CryptoUtil;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

@RequiredArgsConstructor
@Getter
@Configuration
public class AuthConfig {
    private final ResourceLoader resourceLoader;

    @Value("${security.authentication.enabled:false}")
    private Boolean authModeEnabled;

    @Value("${security.authentication.allow-get-endpoints:false}")
    private Boolean publicGetEndpointsEnabled;

    @Value("${security.authentication.api-key.prefix:snst}")
    private String apiKeyPrefix;

    @Value("${security.authentication.api-key.header:X-API-Key}")
    private String apiKeyHeader;

    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    @Value("${security.authentication.private-key}")
    public void setPrivateKey(final String privateKeyPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        final Resource priv = resourceLoader.getResource(privateKeyPath);
        this.privateKey = CryptoUtil.parsePrivateKey(priv.getContentAsString(StandardCharsets.UTF_8));
    }

    @Value("${security.authentication.public-key}")
    public void setPublicKey(final String publicKeyPath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        final Resource pub = resourceLoader.getResource(publicKeyPath);
        this.publicKey = CryptoUtil.parsePublicKey(pub.getContentAsString(StandardCharsets.UTF_8));
    }

}
