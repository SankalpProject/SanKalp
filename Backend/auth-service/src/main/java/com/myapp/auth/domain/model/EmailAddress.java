package com.myapp.auth.domain.model;

import com.myapp.auth.domain.exception.AuthException;

import java.util.Locale;
import java.util.regex.Pattern;

/**
 * Value object for an email address, normalised to lower case.
 * <p>
 * Invariants are enforced at construction, so every EmailAddress in the system is valid.
 * {@link #toString()} is masked so the full address (PII) never leaks into logs by accident.
 */
public record EmailAddress(String value) {

    private static final int MAX_LENGTH = 254; // RFC 5321
    private static final String LABEL = "[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?";
    private static final Pattern FORMAT = Pattern.compile(
            "^[a-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@" + LABEL + "(?:\\." + LABEL + ")+$");

    public EmailAddress {
        if (value == null || value.length() > MAX_LENGTH || !FORMAT.matcher(value).matches()) {
            throw AuthException.invalidEmail();
        }
    }

    public static EmailAddress of(String raw) {
        return new EmailAddress(raw == null ? null : raw.trim().toLowerCase(Locale.ROOT));
    }

    /** "satyam@gmail.com" -> "s***@gmail.com" */
    public String masked() {
        int at = value.indexOf('@');
        return value.charAt(0) + "***" + value.substring(at);
    }

    @Override
    public String toString() {
        return masked();
    }
}
