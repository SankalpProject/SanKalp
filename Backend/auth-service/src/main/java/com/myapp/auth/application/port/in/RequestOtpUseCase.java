package com.myapp.auth.application.port.in;

import com.myapp.auth.domain.model.EmailAddress;

import java.time.Duration;

public interface RequestOtpUseCase {

    OtpRequested requestOtp(RequestOtpCommand command);

    record RequestOtpCommand(EmailAddress email, String clientIp) {
    }

    record OtpRequested(Duration expiresIn, Duration resendAvailableIn) {
    }
}
