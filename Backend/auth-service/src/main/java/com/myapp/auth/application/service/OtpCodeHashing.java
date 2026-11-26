package com.myapp.auth.application.service;

import com.myapp.auth.application.port.out.SecretHasher;
import com.myapp.auth.domain.model.EmailAddress;

/** Binds the OTP hash to the email address, so a hash can never be reused for another account. */
final class OtpCodeHashing {

    private OtpCodeHashing() {
    }

    static String hash(SecretHasher hasher, EmailAddress email, String code) {
        return hasher.hash(input(email, code));
    }

    static boolean matches(SecretHasher hasher, EmailAddress email, String code, String expectedHash) {
        return hasher.matches(input(email, code), expectedHash);
    }

    private static String input(EmailAddress email, String code) {
        return "otp:" + email.value() + ":" + code;
    }
}
