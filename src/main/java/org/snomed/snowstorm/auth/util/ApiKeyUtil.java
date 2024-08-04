package org.snomed.snowstorm.auth.util;

import lombok.experimental.UtilityClass;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Optional;

public final class ApiKeyUtil {

    private ApiKeyUtil() {}

    /**
     * @return the signed API Key
     */
    public static SignedApiKey generateSignedApiKey(final String apiKeyPrefix, final RSAPrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final String apiKey = CryptoUtil.generateApiKey();
        return new SignedApiKey(apiKeyPrefix, apiKey, CryptoUtil.createRSASignature(apiKey, privateKey));
    }

    /**
     * @param signedApiKey the signed API Key
     * @return the nullable optional of the API Key, empty if signature couldn't be verified
     */
    public static Optional<SignedApiKey> verifySignedApiKey(final String apiKeyPrefix, final RSAPublicKey publicKey, final String signedApiKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final String prefix = apiKeyPrefix + SignedApiKey.PREFIX_SEPARATOR;

        if (!signedApiKey.startsWith(prefix)) {
            return Optional.empty();
        }

        final int lastSignatureSeparator = signedApiKey.lastIndexOf(SignedApiKey.SIGNATURE_SEPARATOR);

        final String apiKey = signedApiKey.substring(prefix.length(), lastSignatureSeparator);
        final String base64encodedSignature = signedApiKey.substring(lastSignatureSeparator + 1);

        if (CryptoUtil.verifyRSASignature(apiKey, base64encodedSignature, publicKey)) {
            return Optional.of(new SignedApiKey(apiKeyPrefix, apiKey, base64encodedSignature));
        } else {
            return Optional.empty();
        }
    }

}
