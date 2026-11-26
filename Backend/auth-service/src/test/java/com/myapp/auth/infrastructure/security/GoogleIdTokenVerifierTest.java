package com.myapp.auth.infrastructure.security;

import com.myapp.auth.domain.exception.AuthException;
import com.myapp.auth.domain.exception.ErrorCode;
import com.myapp.auth.domain.model.ExternalIdentity;
import com.myapp.auth.domain.model.IdentityProvider;
import com.myapp.auth.support.FakeGoogle;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class GoogleIdTokenVerifierTest {

    private final GoogleIdTokenVerifier verifier = FakeGoogle.verifier();

    @Test
    void acceptsValidTokenAndNormalisesEmail() {
        ExternalIdentity identity = verifier.verify(FakeGoogle.token().email("Satyam@Example.COM").build());
        assertThat(identity.provider()).isEqualTo(IdentityProvider.GOOGLE);
        assertThat(identity.subject()).isEqualTo("google-user-123");
        assertThat(identity.email().value()).isEqualTo("satyam@example.com");
        assertThat(identity.emailVerified()).isTrue();
    }

    @Test
    void acceptsLegacyIssuerForm() {
        assertThat(verifier.verify(FakeGoogle.token().issuer("accounts.google.com").build())).isNotNull();
    }

    @Test
    void reportsUnverifiedEmail() {
        assertThat(verifier.verify(FakeGoogle.token().emailVerified(false).build()).emailVerified()).isFalse();
    }

    @Test
    void rejectsTokenIssuedForAnotherApp() {
        assertRejected(FakeGoogle.token().audience("someone-elses-app.apps.googleusercontent.com").build());
    }

    @Test
    void rejectsWrongIssuer() {
        assertRejected(FakeGoogle.token().issuer("https://evil.example").build());
    }

    @Test
    void rejectsExpiredToken() {
        assertRejected(FakeGoogle.token().expiresAt(Instant.now().minus(Duration.ofMinutes(5))).build());
    }

    @Test
    void rejectsForgedSignature() {
        assertRejected(FakeGoogle.token().signedByAttacker().build());
    }

    @Test
    void rejectsGarbage() {
        assertRejected("not-a-jwt");
        assertRejected("");
        assertRejected("x".repeat(5000));
    }

    private void assertRejected(String token) {
        assertThatThrownBy(() -> verifier.verify(token))
                .isInstanceOf(AuthException.class)
                .extracting(e -> ((AuthException) e).code())
                .isEqualTo(ErrorCode.INVALID_EXTERNAL_TOKEN);
    }
}
