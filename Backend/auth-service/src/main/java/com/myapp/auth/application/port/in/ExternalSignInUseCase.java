package com.myapp.auth.application.port.in;

import com.myapp.auth.domain.model.AuthTokens;
import com.myapp.auth.domain.model.IdentityProvider;

/** Sign in with an ID token issued by an external provider (Google today, Apple later). */
public interface ExternalSignInUseCase {

    AuthTokens signIn(ExternalSignInCommand command);

    record ExternalSignInCommand(IdentityProvider provider, String idToken, String clientIp) {
        @Override
        public String toString() {
            return "ExternalSignInCommand[provider=" + provider + ", clientIp=" + clientIp + "]";
        }
    }
}
