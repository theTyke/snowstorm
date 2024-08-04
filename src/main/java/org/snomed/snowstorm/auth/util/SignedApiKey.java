package org.snomed.snowstorm.auth.util;

public record SignedApiKey(String prefix, String secret, String signature) {

    public static char PREFIX_SEPARATOR = '_';
    public static char SIGNATURE_SEPARATOR = '.';

    @Override
    public String toString() {
        return this.prefix + PREFIX_SEPARATOR + this.secret + SIGNATURE_SEPARATOR + this.signature;
    }
}
