package com.myapp.auth.application.port.out;

import com.myapp.auth.domain.model.ExternalIdentity;
import com.myapp.auth.domain.model.IdentityProvider;

/**
 * Verifies a provider ID token (signature, issuer, audience, expiry) and extracts the identity.
 * Must throw {@code AuthException.invalidExternalToken()} for any token that fails verification.
 */
public interface ExternalIdentityVerifier {

    IdentityProvider provider();

    ExternalIdentity verify(String idToken);
}
