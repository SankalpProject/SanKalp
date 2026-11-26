package com.myapp.auth.support;

import com.myapp.auth.infrastructure.security.GoogleIdTokenVerifier;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Stands in for Google in tests: signs ID tokens with a local RSA key and builds a {@link GoogleIdTokenVerifier}
 * that trusts that key. Everything else (issuer, audience, expiry checks) is the real production code.
 */
public final class FakeGoogle {

    public static final String CLIENT_ID = "test-client-id.apps.googleusercontent.com";

    private static final RSAKey KEY = generate();
    private static final RSAKey OTHER_KEY = generate();

    private FakeGoogle() {
    }

    public static GoogleIdTokenVerifier verifier() {
        try {
            return new GoogleIdTokenVerifier(NimbusJwtDecoder.withPublicKey(KEY.toRSAPublicKey()).build(),
                    List.of(CLIENT_ID));
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }

    public static Builder token() {
        return new Builder();
    }

    public static final class Builder {
        private String issuer = "https://accounts.google.com";
        private String audience = CLIENT_ID;
        private String subject = "google-user-123";
        private String email = "satyam@example.com";
        private boolean emailVerified = true;
        private Instant expiresAt = Instant.now().plus(Duration.ofMinutes(30));
        private RSAKey signingKey = KEY;

        public Builder issuer(String v) { issuer = v; return this; }
        public Builder audience(String v) { audience = v; return this; }
        public Builder subject(String v) { subject = v; return this; }
        public Builder email(String v) { email = v; return this; }
        public Builder emailVerified(boolean v) { emailVerified = v; return this; }
        public Builder expiresAt(Instant v) { expiresAt = v; return this; }
        public Builder signedByAttacker() { signingKey = OTHER_KEY; return this; }

        public String build() {
            JwtClaimsSet claims = JwtClaimsSet.builder()
                    .issuer(issuer)
                    .audience(List.of(audience))
                    .subject(subject)
                    .issuedAt(expiresAt.minus(Duration.ofHours(1)))
                    .expiresAt(expiresAt)
                    .claim("email", email)
                    .claim("email_verified", emailVerified)
                    .build();
            NimbusJwtEncoder encoder = new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(signingKey)));
            return encoder.encode(JwtEncoderParameters.from(
                    JwsHeader.with(SignatureAlgorithm.RS256).keyId(signingKey.getKeyID()).build(), claims))
                    .getTokenValue();
        }
    }

    private static RSAKey generate() {
        try {
            return new RSAKeyGenerator(2048).keyIDFromThumbprint(true).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException(e);
        }
    }
}
