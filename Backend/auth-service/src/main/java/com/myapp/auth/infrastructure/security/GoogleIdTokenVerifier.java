package com.myapp.auth.infrastructure.security;

import com.myapp.auth.application.port.out.ExternalIdentityVerifier;
import com.myapp.auth.domain.exception.AuthException;
import com.myapp.auth.domain.model.EmailAddress;
import com.myapp.auth.domain.model.ExternalIdentity;
import com.myapp.auth.domain.model.IdentityProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.List;
import java.util.Set;

/**
 * Verifies Google ID tokens locally (no call per login): signature against Google's published keys
 * (JWKS, cached by Nimbus), issuer, audience = OUR OAuth client id(s), expiry.
 * <p>
 * The audience check is critical: without it, an ID token issued to ANY other app using Google Sign-In
 * could be replayed against our API.
 */
public final class GoogleIdTokenVerifier implements ExternalIdentityVerifier {

    public static final String GOOGLE_JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs";
    private static final Set<String> GOOGLE_ISSUERS = Set.of("https://accounts.google.com", "accounts.google.com");
    private static final int MAX_TOKEN_LENGTH = 4096;

    private static final Logger log = LoggerFactory.getLogger(GoogleIdTokenVerifier.class);

    private final JwtDecoder decoder;

    public GoogleIdTokenVerifier(List<String> allowedClientIds) {
        this(NimbusJwtDecoder.withJwkSetUri(GOOGLE_JWKS_URI)
                        .jwsAlgorithm(SignatureAlgorithm.RS256)
                        .restOperations(restTemplateWithTimeouts())
                        .build(),
                allowedClientIds);
    }

    private static RestTemplate restTemplateWithTimeouts() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(Duration.ofSeconds(3));
        factory.setReadTimeout(Duration.ofSeconds(3));
        return new RestTemplate(factory);
    }

    /** Visible for tests: accepts any decoder (e.g. one backed by a local test key). */
    public GoogleIdTokenVerifier(JwtDecoder decoder, List<String> allowedClientIds) {
        if (allowedClientIds.isEmpty()) {
            log.warn("No Google client ids configured (auth.google.client-ids): Google sign-in is disabled.");
        }
        if (decoder instanceof NimbusJwtDecoder nimbus) {
            nimbus.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                    new JwtTimestampValidator(),
                    new JwtClaimValidator<String>(JwtClaimNames.ISS, GOOGLE_ISSUERS::contains),
                    new JwtClaimValidator<List<String>>(JwtClaimNames.AUD,
                            aud -> aud != null && aud.stream().anyMatch(allowedClientIds::contains))));
        }
        this.decoder = decoder;
    }

    @Override
    public IdentityProvider provider() {
        return IdentityProvider.GOOGLE;
    }

    @Override
    public ExternalIdentity verify(String idToken) {
        if (idToken == null || idToken.isBlank() || idToken.length() > MAX_TOKEN_LENGTH) {
            throw AuthException.invalidExternalToken();
        }
        try {
            Jwt jwt = decoder.decode(idToken);
            String email = jwt.getClaimAsString("email");
            if (email == null) {
                throw AuthException.invalidExternalToken();
            }
            return new ExternalIdentity(
                    IdentityProvider.GOOGLE,
                    jwt.getSubject(),
                    EmailAddress.of(email),
                    Boolean.TRUE.equals(jwt.getClaimAsBoolean("email_verified")));
        } catch (JwtException | IllegalArgumentException e) {
            log.info("Rejected Google ID token: {}", e.getClass().getSimpleName()); // never log the token
            throw AuthException.invalidExternalToken();
        }
    }
}
