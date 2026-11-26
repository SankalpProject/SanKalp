package com.myapp.auth.domain.model;

import java.util.Objects;

/**
 * An identity asserted by an external provider after its token was cryptographically verified.
 * {@code subject} is the provider's stable user id; emails can change, the subject never does.
 */
public record ExternalIdentity(IdentityProvider provider, String subject, EmailAddress email, boolean emailVerified) {

    public ExternalIdentity {
        Objects.requireNonNull(provider, "provider");
        Objects.requireNonNull(email, "email");
        if (subject == null || subject.isBlank()) {
            throw new IllegalArgumentException("subject is required");
        }
    }
}
