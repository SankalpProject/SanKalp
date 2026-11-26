package com.myapp.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.myapp.auth.application.port.out.ExternalIdentityVerifier;
import com.myapp.auth.application.port.out.OtpSender;
import com.myapp.auth.domain.model.EmailAddress;
import com.myapp.auth.support.FakeGoogle;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.convention.TestBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@ActiveProfiles("test") // isolated from the developer's local secrets.properties
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD) // fresh stores/rate limits per test
class AuthFlowIntegrationTest {

    @TestConfiguration
    static class CapturingSenderConfig {
        @Bean
        @Primary
        CapturingOtpSender capturingOtpSender() {
            return new CapturingOtpSender();
        }
    }

    static class CapturingOtpSender implements OtpSender {
        final Map<String, String> lastCode = new ConcurrentHashMap<>();

        @Override
        public void send(EmailAddress email, String code, Duration validFor) {
            lastCode.put(email.value(), code);
        }
    }

    /** Replaces the real Google verifier with one that trusts the FakeGoogle test key. */
    @TestBean(name = "googleIdTokenVerifier")
    ExternalIdentityVerifier googleVerifier;

    static ExternalIdentityVerifier googleVerifier() {
        return FakeGoogle.verifier();
    }

    private static final String EMAIL = "satyam@example.com";

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired CapturingOtpSender sender;

    // ---------------- email OTP ----------------

    @Test
    void emailOtpLogin_thenHelloWorld() throws Exception {
        requestOtp(EMAIL).andExpect(status().isAccepted())
                .andExpect(jsonPath("$.expiresInSeconds").value(600));

        JsonNode tokens = body(verify(EMAIL, sender.lastCode.get(EMAIL)).andExpect(status().isOk()));
        assertThat(tokens.get("tokenType").asText()).isEqualTo("Bearer");
        assertHelloWorld(tokens);
    }

    @Test
    void emailIsCaseInsensitive() throws Exception {
        requestOtp("Satyam@Example.COM").andExpect(status().isAccepted());
        verify("satyam@example.com", sender.lastCode.get(EMAIL)).andExpect(status().isOk());
    }

    @Test
    void protectedEndpointRequiresValidToken() throws Exception {
        mvc.perform(get("/api/v1/home")).andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHORIZED"));
        mvc.perform(get("/api/v1/home").header("Authorization", "Bearer forged.token.value"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void otpIsSingleUse() throws Exception {
        requestOtp(EMAIL);
        String code = sender.lastCode.get(EMAIL);
        verify(EMAIL, code).andExpect(status().isOk());
        verify(EMAIL, code).andExpect(status().isUnauthorized()).andExpect(jsonPath("$.code").value("OTP_INVALID"));
    }

    @Test
    void bruteForceLocksChallengeAfterMaxAttempts() throws Exception {
        requestOtp(EMAIL);
        String real = sender.lastCode.get(EMAIL);
        String wrong = real.equals("000000") ? "111111" : "000000";
        for (int i = 0; i < 4; i++) {
            verify(EMAIL, wrong).andExpect(jsonPath("$.code").value("OTP_INVALID"));
        }
        verify(EMAIL, wrong).andExpect(jsonPath("$.code").value("OTP_ATTEMPTS_EXCEEDED"));
        // Even the correct code no longer works: the challenge was destroyed.
        verify(EMAIL, real).andExpect(status().isUnauthorized());
    }

    @Test
    void resendIsThrottled() throws Exception {
        requestOtp(EMAIL).andExpect(status().isAccepted());
        requestOtp(EMAIL).andExpect(status().isTooManyRequests())
                .andExpect(header().exists("Retry-After"))
                .andExpect(jsonPath("$.code").value("OTP_RESEND_TOO_SOON"));
    }

    @Test
    void invalidInputIsRejectedWithoutEchoingIt() throws Exception {
        mvc.perform(post("/api/v1/auth/otp/request").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"<script>alert(1)</script>\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.fields[0]").value("email"));
    }

    // ---------------- Google ----------------

    @Test
    void googleSignIn_thenHelloWorld() throws Exception {
        JsonNode tokens = body(google(FakeGoogle.token().build()).andExpect(status().isOk()));
        assertHelloWorld(tokens);
    }

    @Test
    void googleAndEmailOtpResolveToTheSameAccount() throws Exception {
        requestOtp(EMAIL);
        String emailUser = userIdOf(body(verify(EMAIL, sender.lastCode.get(EMAIL))));

        String googleUser = userIdOf(body(google(FakeGoogle.token().email(EMAIL).build())));
        assertThat(googleUser).isEqualTo(emailUser);

        // Returning Google user is found by Google subject even if their Google email changed later.
        String again = userIdOf(body(google(FakeGoogle.token().email("new-address@example.com").build())));
        assertThat(again).isEqualTo(emailUser);
    }

    @Test
    void googleTokenForAnotherAppIsRejected() throws Exception {
        google(FakeGoogle.token().audience("other-app.apps.googleusercontent.com").build())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_EXTERNAL_TOKEN"));
    }

    @Test
    void forgedGoogleTokenIsRejected() throws Exception {
        google(FakeGoogle.token().signedByAttacker().build())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_EXTERNAL_TOKEN"));
    }

    @Test
    void unverifiedGoogleEmailCannotTakeOverAccount() throws Exception {
        requestOtp(EMAIL);
        verify(EMAIL, sender.lastCode.get(EMAIL)).andExpect(status().isOk());

        google(FakeGoogle.token().subject("attacker").email(EMAIL).emailVerified(false).build())
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("EXTERNAL_EMAIL_NOT_VERIFIED"));
    }

    // ---------------- sessions ----------------

    @Test
    void refreshRotatesAndDetectsReuse() throws Exception {
        String r1 = body(google(FakeGoogle.token().build())).get("refreshToken").asText();

        String r2 = body(refresh(r1).andExpect(status().isOk())).get("refreshToken").asText();
        assertThat(r2).isNotEqualTo(r1);

        // Replaying the old token revokes the whole family, including r2.
        refresh(r1).andExpect(status().isUnauthorized());
        refresh(r2).andExpect(status().isUnauthorized());
    }

    @Test
    void logoutRevokesRefreshToken() throws Exception {
        String refreshToken = body(google(FakeGoogle.token().build())).get("refreshToken").asText();
        mvc.perform(post("/api/v1/auth/logout").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("refreshToken", refreshToken))))
                .andExpect(status().isNoContent());
        refresh(refreshToken).andExpect(status().isUnauthorized());
    }

    // ---------------- helpers ----------------

    private void assertHelloWorld(JsonNode tokens) throws Exception {
        mvc.perform(get("/api/v1/home").header("Authorization", "Bearer " + tokens.get("accessToken").asText()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.message").value("Hello World"));
    }

    private String userIdOf(JsonNode tokens) throws Exception {
        String response = mvc.perform(get("/api/v1/home")
                        .header("Authorization", "Bearer " + tokens.get("accessToken").asText()))
                .andReturn().getResponse().getContentAsString();
        return json.readTree(response).get("userId").asText();
    }

    private ResultActions requestOtp(String email) throws Exception {
        return postJson("/api/v1/auth/otp/request", Map.of("email", email));
    }

    private ResultActions verify(String email, String code) throws Exception {
        return postJson("/api/v1/auth/otp/verify", Map.of("email", email, "code", code));
    }

    private ResultActions google(String idToken) throws Exception {
        return postJson("/api/v1/auth/google", Map.of("idToken", idToken));
    }

    private ResultActions refresh(String token) throws Exception {
        return postJson("/api/v1/auth/token/refresh", Map.of("refreshToken", token));
    }

    private ResultActions postJson(String path, Map<String, String> body) throws Exception {
        return mvc.perform(post(path)
                .contentType(MediaType.APPLICATION_JSON)
                .content(json.writeValueAsString(body)));
    }

    private JsonNode body(ResultActions result) throws Exception {
        return json.readTree(result.andReturn().getResponse().getContentAsString());
    }
}
