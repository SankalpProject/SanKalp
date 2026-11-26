package com.myapp.auth.application.port.in;

import com.myapp.auth.domain.model.AuthTokens;

public interface RefreshTokenUseCase {

    AuthTokens refresh(RefreshCommand command);

    record RefreshCommand(String refreshToken, String clientIp) {
        @Override
        public String toString() {
            return "RefreshCommand[clientIp=" + clientIp + "]";
        }
    }
}
