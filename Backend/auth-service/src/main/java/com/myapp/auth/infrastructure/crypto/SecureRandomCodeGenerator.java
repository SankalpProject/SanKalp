package com.myapp.auth.infrastructure.crypto;

import com.myapp.auth.application.port.out.SecureCodeGenerator;

import java.security.SecureRandom;
import java.util.Base64;
import java.util.UUID;

/** Uses {@link SecureRandom} (CSPRNG). Never use java.util.Random / Math.random for secrets. */
public final class SecureRandomCodeGenerator implements SecureCodeGenerator {

    private final SecureRandom random = new SecureRandom();

    @Override
    public String numericCode(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(random.nextInt(10)); // uniform, no modulo bias
        }
        return sb.toString();
    }

    @Override
    public String opaqueToken(int bytes) {
        byte[] buffer = new byte[bytes];
        random.nextBytes(buffer);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buffer);
    }

    @Override
    public String randomId() {
        return UUID.randomUUID().toString();
    }
}
