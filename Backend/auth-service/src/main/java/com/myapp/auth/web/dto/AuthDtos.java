package com.myapp.auth.web.dto;

import com.myapp.auth.domain.model.AuthTokens;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.Duration;
import java.time.Instant;

/** Request/response contracts. Kept separate from domain objects so the API can evolve independently. */
public final class AuthDtos {

    private AuthDtos() {
    }

    public record RequestOtpRequest(@NotBlank @Email @Size(max = 254) String email) {
    }

    public record VerifyOtpRequest(
            @NotBlank @Email @Size(max = 254) String email,
            @NotBlank @Pattern(regexp = "^\\d{4,8}$", message = "must be numeric") String code) {
        @Override
        public String toString() {
            return "VerifyOtpRequest[code=***]";
        }
    }

    public record GoogleSignInRequest(@NotBlank @Size(max = 4096) String idToken) {
        @Override
        public String toString() {
            return "GoogleSignInRequest[***]";
        }
    }

    public record RefreshTokenRequest(@NotBlank @Size(max = 512) String refreshToken) {
        @Override
        public String toString() {
            return "RefreshTokenRequest[***]";
        }
    }

    public record OtpRequestedResponse(long expiresInSeconds, long resendAfterSeconds) {
        public static OtpRequestedResponse of(Duration expiresIn, Duration resendAfter) {
            return new OtpRequestedResponse(expiresIn.toSeconds(), resendAfter.toSeconds());
        }
    }

    public record TokenResponse(
            String tokenType,
            String accessToken,
            long expiresIn,
            String refreshToken,
            long refreshExpiresIn) {

        public static TokenResponse from(AuthTokens tokens, Instant now) {
            return new TokenResponse(
                    "Bearer",
                    tokens.accessToken(),
                    Duration.between(now, tokens.accessTokenExpiresAt()).toSeconds(),
                    tokens.refreshToken(),
                    Duration.between(now, tokens.refreshTokenExpiresAt()).toSeconds());
        }

        @Override
        public String toString() {
            return "TokenResponse[expiresIn=" + expiresIn + "]";
        }
    }
}
