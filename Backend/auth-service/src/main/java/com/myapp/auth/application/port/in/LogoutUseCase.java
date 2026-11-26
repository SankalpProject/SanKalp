package com.myapp.auth.application.port.in;

public interface LogoutUseCase {

    /** Revokes the refresh token's whole family. Idempotent: unknown tokens are ignored. */
    void logout(String refreshToken);
}
