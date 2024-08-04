package org.snomed.snowstorm.auth.util;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public final class CryptoUtil {

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder();
    private static final Base64.Decoder base64Decoder = Base64.getUrlDecoder();

    private CryptoUtil() {}

    public static String createRSASignature(final String apiKey, final RSAPrivateKey privateKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final Signature signature = Signature.getInstance("SHA512withRSA");
        signature.initSign(privateKey);
        signature.update(apiKey.getBytes(StandardCharsets.UTF_8));
        final byte[] signatureValue = signature.sign();
        return base64Encoder.encodeToString(signatureValue);
    }

    public static boolean verifyRSASignature(final String apiKey, final String base64encodedSignature, final RSAPublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        final byte[] signatureValue = base64Decoder.decode(base64encodedSignature);
        final Signature signature = Signature.getInstance("SHA512withRSA");
        signature.initVerify(publicKey);
        signature.update(apiKey.getBytes(StandardCharsets.UTF_8));
        return signature.verify(signatureValue);
    }

    public static String generateApiKey() {
        final byte[] bytes = new byte[48];
        secureRandom.nextBytes(bytes);
        return base64Encoder.encodeToString(bytes);
    }

    public static RSAPrivateKey parsePrivateKey(final String fileContent) throws NoSuchAlgorithmException, InvalidKeySpecException {
        final String privPEM = parsePEM(fileContent);
        final PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privPEM));
        return (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    public static RSAPublicKey parsePublicKey(final String fileContent) throws NoSuchAlgorithmException, InvalidKeySpecException {
        final String pubPEM = parsePEM(fileContent);
        final X509EncodedKeySpec spec = new X509EncodedKeySpec(Base64.getDecoder().decode(pubPEM));
        return (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    private static String parsePEM(final String content) {
        return content.replaceAll("-{3,}[\sA-Z]*-{3,}", "").replaceAll("\r", "").replaceAll("\n", "");
    }

}