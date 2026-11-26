package com.myapp.auth.application.port.out;

/** Cryptographically secure random values. */
public interface SecureCodeGenerator {

    /** Numeric code of the given length, e.g. "042917". */
    String numericCode(int length);

    /** URL-safe opaque token with the given number of random bytes. */
    String opaqueToken(int bytes);

    String randomId();
}
