package com.myapp.auth.infrastructure.security;

import com.myapp.auth.application.port.out.AccessTokenIssuer;
import com.myapp.auth.domain.model.User;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

/**
 * Signs short-lived RS256 access tokens. Asymmetric keys let other microservices verify tokens
 * with only the public key (served via JWKS) — they can never mint tokens.
 * The token carries no PII: subject is the opaque user id, not the phone number.
 */
public final class JwtAccessTokenIssuer implements AccessTokenIssuer {

    private final JwtEncoder encoder;
    private final String issuer;
    private final String audience;
    private final Duration ttl;
    private final String keyId;

    public JwtAccessTokenIssuer(JwtEncoder encoder, String issuer, String audience, Duration ttl, String keyId) {
        this.encoder = encoder;
        this.issuer = issuer;
        this.audience = audience;
        this.ttl = ttl;
        this.keyId = keyId;
    }

    @Override
    public IssuedAccessToken issue(User user, Instant now) {
        Instant expiresAt = now.plus(ttl);
        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(issuer)
                .audience(List.of(audience))
                .subject(user.id().toString())
                .issuedAt(now)
                .notBefore(now)
                .expiresAt(expiresAt)
                .id(UUID.randomUUID().toString())
                .claim("scope", "user")
                .build();
        JwsHeader header = JwsHeader.with(SignatureAlgorithm.RS256).keyId(keyId).build();
        String token = encoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
        return new IssuedAccessToken(token, expiresAt);
    }
}
