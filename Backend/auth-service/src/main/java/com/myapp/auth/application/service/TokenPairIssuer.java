package com.myapp.auth.application.service;

import com.myapp.auth.application.port.out.AccessTokenIssuer;
import com.myapp.auth.application.port.out.RefreshTokenStore;
import com.myapp.auth.application.port.out.SecretHasher;
import com.myapp.auth.application.port.out.SecureCodeGenerator;
import com.myapp.auth.domain.model.AuthTokens;
import com.myapp.auth.domain.model.RefreshToken;
import com.myapp.auth.domain.model.User;

import java.time.Instant;

/** Creates an access token + refresh token pair. Single responsibility, shared by login and refresh. */
public final class TokenPairIssuer {

    private final AccessTokenIssuer accessTokenIssuer;
    private final RefreshTokenStore refreshTokenStore;
    private final SecureCodeGenerator codeGenerator;
    private final SecretHasher hasher;
    private final TokenPolicy policy;

    public TokenPairIssuer(AccessTokenIssuer accessTokenIssuer,
                           RefreshTokenStore refreshTokenStore,
                           SecureCodeGenerator codeGenerator,
                           SecretHasher hasher,
                           TokenPolicy policy) {
        this.accessTokenIssuer = accessTokenIssuer;
        this.refreshTokenStore = refreshTokenStore;
        this.codeGenerator = codeGenerator;
        this.hasher = hasher;
        this.policy = policy;
    }

    /** New login: starts a new refresh-token family. */
    public AuthTokens issueNewSession(User user, Instant now) {
        return issue(user, codeGenerator.randomId(), now);
    }

    /** Rotation: the new refresh token joins the existing family. */
    public AuthTokens rotate(User user, String familyId, Instant now) {
        return issue(user, familyId, now);
    }

    private AuthTokens issue(User user, String familyId, Instant now) {
        AccessTokenIssuer.IssuedAccessToken access = accessTokenIssuer.issue(user, now);

        String refreshValue = codeGenerator.opaqueToken(TokenPolicy.REFRESH_TOKEN_BYTES);
        Instant refreshExpiresAt = now.plus(policy.refreshTokenTtl());
        refreshTokenStore.save(RefreshToken.issue(hasher.hash(refreshValue), user.id(), familyId, now, refreshExpiresAt));

        return new AuthTokens(access.value(), access.expiresAt(), refreshValue, refreshExpiresAt);
    }
}
