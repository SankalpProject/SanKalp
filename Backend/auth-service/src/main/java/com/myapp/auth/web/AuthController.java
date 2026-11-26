package com.myapp.auth.web;

import com.myapp.auth.application.port.in.ExternalSignInUseCase;
import com.myapp.auth.application.port.in.LogoutUseCase;
import com.myapp.auth.application.port.in.RefreshTokenUseCase;
import com.myapp.auth.application.port.in.RequestOtpUseCase;
import com.myapp.auth.application.port.in.VerifyOtpUseCase;
import com.myapp.auth.domain.model.AuthTokens;
import com.myapp.auth.domain.model.EmailAddress;
import com.myapp.auth.domain.model.IdentityProvider;
import com.myapp.auth.web.dto.AuthDtos.GoogleSignInRequest;
import com.myapp.auth.web.dto.AuthDtos.OtpRequestedResponse;
import com.myapp.auth.web.dto.AuthDtos.RefreshTokenRequest;
import com.myapp.auth.web.dto.AuthDtos.RequestOtpRequest;
import com.myapp.auth.web.dto.AuthDtos.TokenResponse;
import com.myapp.auth.web.dto.AuthDtos.VerifyOtpRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Clock;

/**
 * Thin HTTP adapter: validates input, maps DTOs to commands, delegates to use cases.
 * Depends only on use-case interfaces (Interface Segregation + Dependency Inversion).
 */
@RestController
@RequestMapping(path = "/api/v1/auth")
public class AuthController {

    private final RequestOtpUseCase requestOtp;
    private final VerifyOtpUseCase verifyOtp;
    private final ExternalSignInUseCase externalSignIn;
    private final RefreshTokenUseCase refreshToken;
    private final LogoutUseCase logout;
    private final ClientIpResolver clientIpResolver;
    private final Clock clock;

    public AuthController(RequestOtpUseCase requestOtp,
                          VerifyOtpUseCase verifyOtp,
                          ExternalSignInUseCase externalSignIn,
                          RefreshTokenUseCase refreshToken,
                          LogoutUseCase logout,
                          ClientIpResolver clientIpResolver,
                          Clock clock) {
        this.requestOtp = requestOtp;
        this.verifyOtp = verifyOtp;
        this.externalSignIn = externalSignIn;
        this.refreshToken = refreshToken;
        this.logout = logout;
        this.clientIpResolver = clientIpResolver;
        this.clock = clock;
    }

    @PostMapping("/otp/request")
    public ResponseEntity<OtpRequestedResponse> requestOtp(@Valid @RequestBody RequestOtpRequest body,
                                                           HttpServletRequest request) {
        var result = requestOtp.requestOtp(new RequestOtpUseCase.RequestOtpCommand(
                EmailAddress.of(body.email()), clientIpResolver.resolve(request)));
        return ResponseEntity.accepted().body(OtpRequestedResponse.of(result.expiresIn(), result.resendAvailableIn()));
    }

    @PostMapping("/otp/verify")
    public TokenResponse verifyOtp(@Valid @RequestBody VerifyOtpRequest body, HttpServletRequest request) {
        AuthTokens tokens = verifyOtp.verifyOtp(new VerifyOtpUseCase.VerifyOtpCommand(
                EmailAddress.of(body.email()), body.code(), clientIpResolver.resolve(request)));
        return TokenResponse.from(tokens, clock.instant());
    }

    @PostMapping("/google")
    public TokenResponse signInWithGoogle(@Valid @RequestBody GoogleSignInRequest body, HttpServletRequest request) {
        AuthTokens tokens = externalSignIn.signIn(new ExternalSignInUseCase.ExternalSignInCommand(
                IdentityProvider.GOOGLE, body.idToken(), clientIpResolver.resolve(request)));
        return TokenResponse.from(tokens, clock.instant());
    }

    @PostMapping("/token/refresh")
    public TokenResponse refresh(@Valid @RequestBody RefreshTokenRequest body, HttpServletRequest request) {
        AuthTokens tokens = refreshToken.refresh(new RefreshTokenUseCase.RefreshCommand(
                body.refreshToken(), clientIpResolver.resolve(request)));
        return TokenResponse.from(tokens, clock.instant());
    }

    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@Valid @RequestBody RefreshTokenRequest body) {
        logout.logout(body.refreshToken());
        return ResponseEntity.noContent().build();
    }
}
