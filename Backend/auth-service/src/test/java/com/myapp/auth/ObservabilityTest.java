package com.myapp.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.myapp.auth.application.port.out.ExternalIdentityVerifier;
import com.myapp.auth.application.port.out.OtpSender;
import com.myapp.auth.domain.model.EmailAddress;
import com.myapp.auth.support.FakeGoogle;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.MeterRegistry;
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
@ActiveProfiles("test")
@AutoConfigureMockMvc
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD) // fresh counters per test
class ObservabilityTest {

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

    @TestBean(name = "googleIdTokenVerifier")
    ExternalIdentityVerifier googleVerifier;

    static ExternalIdentityVerifier googleVerifier() {
        return FakeGoogle.verifier();
    }

    private static final String EMAIL = "obs@example.com";

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired CapturingOtpSender sender;
    @Autowired MeterRegistry meters;

    // ---------------- request correlation ----------------

    @Test
    void everyResponseCarriesARequestId() throws Exception {
        String id = mvc.perform(get("/api/v1/home"))
                .andExpect(header().exists("X-Request-Id"))
                .andReturn().getResponse().getHeader("X-Request-Id");
        assertThat(id).matches("[0-9a-f-]{36}");
    }

    @Test
    void safeIncomingRequestIdIsPropagatedIntoErrorBodies() throws Exception {
        postJson("/api/v1/auth/otp/verify", Map.of("email", EMAIL, "code", "123456"), "mobile-req-12345")
                .andExpect(status().isUnauthorized())
                .andExpect(header().string("X-Request-Id", "mobile-req-12345"))
                .andExpect(jsonPath("$.requestId").value("mobile-req-12345"));
    }

    @Test
    void maliciousRequestIdIsReplacedToPreventLogInjection() throws Exception {
        String id = mvc.perform(get("/api/v1/home").header("X-Request-Id", "abc\nFAKE AUDIT LINE"))
                .andReturn().getResponse().getHeader("X-Request-Id");
        assertThat(id).doesNotContain("FAKE").matches("[0-9a-f-]{36}");
    }

    // ---------------- audit events → metrics ----------------

    @Test
    void loginFailuresAndSuccessesAreCounted() throws Exception {
        postJson("/api/v1/auth/otp/request", Map.of("email", EMAIL), null).andExpect(status().isAccepted());
        postJson("/api/v1/auth/otp/verify", Map.of("email", EMAIL, "code", wrongCode()), null)
                .andExpect(status().isUnauthorized());
        postJson("/api/v1/auth/otp/verify", Map.of("email", EMAIL, "code", sender.lastCode.get(EMAIL)), null)
                .andExpect(status().isOk());

        assertThat(count("OTP_REQUESTED", "email_otp")).isEqualTo(1);
        assertThat(count("LOGIN_FAILED", "email_otp")).isEqualTo(1);
        assertThat(count("USER_REGISTERED", "email_otp")).isEqualTo(1);
        assertThat(count("LOGIN_SUCCEEDED", "email_otp")).isEqualTo(1);
    }

    @Test
    void googleLoginAndRejectedTokensAreCounted() throws Exception {
        postJson("/api/v1/auth/google", Map.of("idToken", FakeGoogle.token().build()), null).andExpect(status().isOk());
        postJson("/api/v1/auth/google", Map.of("idToken", FakeGoogle.token().signedByAttacker().build()), null)
                .andExpect(status().isUnauthorized());

        assertThat(count("LOGIN_SUCCEEDED", "google")).isEqualTo(1);
        assertThat(count("ACCOUNT_LINKED", "google")).isEqualTo(1);
        assertThat(count("LOGIN_FAILED", "google")).isEqualTo(1);
    }

    @Test
    void refreshTokenTheftIsCounted() throws Exception {
        String r1 = json.readTree(postJson("/api/v1/auth/google", Map.of("idToken", FakeGoogle.token().build()), null)
                .andReturn().getResponse().getContentAsString()).get("refreshToken").asText();
        postJson("/api/v1/auth/token/refresh", Map.of("refreshToken", r1), null).andExpect(status().isOk());
        postJson("/api/v1/auth/token/refresh", Map.of("refreshToken", r1), null).andExpect(status().isUnauthorized());

        assertThat(count("TOKEN_REFRESHED", "none")).isEqualTo(1);
        assertThat(count("TOKEN_REUSE_DETECTED", "none")).isEqualTo(1);
    }

    @Test
    void rateLimitHitsAreCountedWithoutPersonalData() throws Exception {
        for (int i = 0; i < 51; i++) { // otp-verify-per-ip limit is 50 / 15 min
            postJson("/api/v1/auth/otp/verify", Map.of("email", "u" + i + "@example.com", "code", "000000"), null);
        }
        assertThat(count("RATE_LIMITED", "none")).isGreaterThanOrEqualTo(1);
        assertThat(meters.find("auth.events").tags("type", "RATE_LIMITED").counters())
                .allSatisfy(c -> assertThat(c.getId().getTags().toString()).doesNotContain("@"));
    }

    // ---------------- actuator exposure ----------------

    @Test
    void healthIsPublicButMetricsAreNotExposedOnTheApiPort() throws Exception {
        mvc.perform(get("/actuator/health")).andExpect(status().isOk());
        mvc.perform(get("/actuator/health/liveness")).andExpect(status().isOk());
        int metricsStatus = mvc.perform(get("/actuator/prometheus")).andReturn().getResponse().getStatus();
        assertThat(metricsStatus).isIn(401, 403, 404);
    }

    // ---------------- helpers ----------------

    private double count(String type, String method) {
        Counter counter = meters.find("auth.events").tags("type", type, "method", method).counter();
        return counter == null ? 0 : counter.count();
    }

    private String wrongCode() {
        String real = sender.lastCode.get(EMAIL);
        return "000000".equals(real) ? "111111" : "000000";
    }

    private ResultActions postJson(String path, Map<String, String> body, String requestId) throws Exception {
        var request = post(path).contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(body));
        if (requestId != null) {
            request.header("X-Request-Id", requestId);
        }
        return mvc.perform(request);
    }
}
