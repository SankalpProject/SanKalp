package com.myapp.auth.application.port.in;

import com.myapp.auth.domain.model.AuthTokens;
import com.myapp.auth.domain.model.EmailAddress;

public interface VerifyOtpUseCase {

    AuthTokens verifyOtp(VerifyOtpCommand command);

    record VerifyOtpCommand(EmailAddress email, String code, String clientIp) {
        @Override
        public String toString() {
            return "VerifyOtpCommand[email=" + email + ", clientIp=" + clientIp + "]"; // never log the code
        }
    }
}
