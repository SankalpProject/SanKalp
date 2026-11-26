package com.myapp.auth.infrastructure.crypto;

import com.myapp.auth.application.port.out.SecretHasher;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * HMAC-SHA256 with a server-side secret ("pepper").
 * <p>
 * A 6-digit OTP has only 10^6 values, so a plain SHA-256 could be brute-forced offline from a leaked hash.
 * Keying the hash with a secret that lives outside the data store (env var / KMS / Vault) prevents that.
 */
public final class HmacSecretHasher implements SecretHasher {

    private static final String ALGORITHM = "HmacSHA256";

    private final SecretKeySpec key;

    public HmacSecretHasher(String pepper) {
        if (pepper == null || pepper.length() < 32) {
            throw new IllegalArgumentException("Hash pepper must be at least 32 characters");
        }
        this.key = new SecretKeySpec(pepper.getBytes(StandardCharsets.UTF_8), ALGORITHM);
    }

    @Override
    public String hash(String secret) {
        try {
            Mac mac = Mac.getInstance(ALGORITHM); // Mac is not thread-safe: one instance per call
            mac.init(key);
            byte[] digest = mac.doFinal(secret.getBytes(StandardCharsets.UTF_8));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC unavailable", e);
        }
    }

    @Override
    public boolean matches(String secret, String expectedHash) {
        if (secret == null || expectedHash == null) {
            return false;
        }
        byte[] actual = hash(secret).getBytes(StandardCharsets.US_ASCII);
        byte[] expected = expectedHash.getBytes(StandardCharsets.US_ASCII);
        return MessageDigest.isEqual(actual, expected); // constant-time
    }
}
