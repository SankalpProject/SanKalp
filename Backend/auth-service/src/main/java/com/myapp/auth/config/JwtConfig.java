package com.myapp.auth.config;

import com.myapp.auth.application.port.out.AccessTokenIssuer;
import com.myapp.auth.infrastructure.security.JwtAccessTokenIssuer;
import com.myapp.auth.infrastructure.security.RsaKeyLoader;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;

@Configuration(proxyBeanMethods = false)
public class JwtConfig {

    private static final Logger log = LoggerFactory.getLogger(JwtConfig.class);

    @Bean
    RSAKey jwtSigningKey(AuthProperties props) throws JOSEException {
        AuthProperties.Jwt jwt = props.jwt();
        KeyPair keyPair;
        if (jwt.publicKey() != null && jwt.privateKey() != null) {
            keyPair = RsaKeyLoader.load(jwt.publicKey(), jwt.privateKey());
        } else if (jwt.allowEphemeralKeys()) {
            log.warn("Using an EPHEMERAL JWT signing key: tokens become invalid on restart. Dev only.");
            keyPair = RsaKeyLoader.generateEphemeral();
        } else {
            // Fail closed: never run production with an accidental, random key.
            throw new IllegalStateException("auth.jwt.public-key and auth.jwt.private-key must be configured");
        }
        return new RSAKey.Builder((RSAPublicKey) keyPair.getPublic())
                .privateKey((RSAPrivateKey) keyPair.getPrivate())
                .keyIDFromThumbprint()
                .build();
    }

    @Bean
    JwtEncoder jwtEncoder(RSAKey key) {
        return new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(key)));
    }

    @Bean
    JwtDecoder jwtDecoder(RSAKey key, AuthProperties props) throws JOSEException {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(key.toRSAPublicKey())
                .signatureAlgorithm(SignatureAlgorithm.RS256) // pin the algorithm: blocks alg=none / HS256 confusion
                .build();
        OAuth2TokenValidator<Jwt> audience = new JwtClaimValidator<List<String>>(
                JwtClaimNames.AUD, aud -> aud != null && aud.contains(props.jwt().audience()));
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(props.jwt().issuer()), // exp, nbf, iss (+ clock skew)
                audience));
        return decoder;
    }

    @Bean
    AccessTokenIssuer accessTokenIssuer(JwtEncoder encoder, RSAKey key, AuthProperties props) {
        AuthProperties.Jwt jwt = props.jwt();
        return new JwtAccessTokenIssuer(encoder, jwt.issuer(), jwt.audience(), jwt.accessTokenTtl(), key.getKeyID());
    }
}
