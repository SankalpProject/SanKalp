package com.myapp.auth;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.myapp.auth.application.port.out.ExternalIdentityVerifier;
import com.myapp.auth.application.port.out.OtpSender;
import com.myapp.auth.application.port.out.UserRepository;
import com.myapp.auth.domain.model.EmailAddress;
import com.myapp.auth.infrastructure.persistence.jdbc.JdbcUserRepository;
import com.myapp.auth.support.FakeGoogle;
import io.zonky.test.db.postgres.embedded.EmbeddedPostgres;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.convention.TestBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/** The whole app on a real PostgreSQL: Flyway migrations run on startup, JDBC adapters are wired. */
@SpringBootTest
@ActiveProfiles("pgtest")
@AutoConfigureMockMvc
class PostgresAuthFlowTest {

    private static final EmbeddedPostgres POSTGRES = start();

    private static EmbeddedPostgres start() {
        try {
            return EmbeddedPostgres.start();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    @DynamicPropertySource
    static void datasource(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", () -> POSTGRES.getJdbcUrl("postgres", "postgres"));
        registry.add("spring.datasource.username", () -> "postgres");
        registry.add("spring.datasource.password", () -> "postgres");
    }

    @AfterAll
    static void stop() throws IOException {
        POSTGRES.close();
    }

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

    @Autowired MockMvc mvc;
    @Autowired ObjectMapper json;
    @Autowired CapturingOtpSender sender;
    @Autowired UserRepository userRepository;
    @Autowired JdbcClient authJdbcClient;

    @Test
    void usesPostgresAdaptersAndAppliesMigrations() {
        assertThat(userRepository).isInstanceOf(JdbcUserRepository.class);
        Integer applied = authJdbcClient
                .sql("SELECT count(*) FROM flyway_schema_history WHERE success")
                .query(Integer.class).single();
        assertThat(applied).isGreaterThanOrEqualTo(1);
    }

    @Test
    void emailAndGoogleLoginPersistToPostgresAndShareOneAccount() throws Exception {
        String email = "pg-user@example.com";
        postJson("/api/v1/auth/otp/request", Map.of("email", email)).andExpect(status().isAccepted());
        JsonNode otpTokens = body(postJson("/api/v1/auth/otp/verify",
                Map.of("email", email, "code", sender.lastCode.get(email))).andExpect(status().isOk()));

        JsonNode googleTokens = body(postJson("/api/v1/auth/google",
                Map.of("idToken", FakeGoogle.token().subject("pg-sub").email(email).build()))
                .andExpect(status().isOk()));

        assertThat(userIdOf(googleTokens)).isEqualTo(userIdOf(otpTokens));
        assertThat(authJdbcClient.sql("SELECT count(*) FROM users WHERE email = :e").param("e", email)
                .query(Long.class).single()).isEqualTo(1L);
        assertThat(authJdbcClient.sql("SELECT count(*) FROM user_identities WHERE subject = 'pg-sub'")
                .query(Long.class).single()).isEqualTo(1L);
    }

    @Test
    void refreshRotationAndReuseDetectionWorkOnPostgres() throws Exception {
        String r1 = body(postJson("/api/v1/auth/google",
                Map.of("idToken", FakeGoogle.token().subject("rot-sub").email("rot@example.com").build())))
                .get("refreshToken").asText();

        String r2 = body(postJson("/api/v1/auth/token/refresh", Map.of("refreshToken", r1))
                .andExpect(status().isOk())).get("refreshToken").asText();

        postJson("/api/v1/auth/token/refresh", Map.of("refreshToken", r1)).andExpect(status().isUnauthorized());
        postJson("/api/v1/auth/token/refresh", Map.of("refreshToken", r2)).andExpect(status().isUnauthorized());

        // Only hashes are stored: the raw token never appears in the database.
        assertThat(authJdbcClient.sql("SELECT count(*) FROM refresh_tokens WHERE token_hash = :t")
                .param("t", r2).query(Long.class).single()).isZero();
    }

    @Test
    void loginsWriteDurableAuditRowsLinkedToTheRequestId() throws Exception {
        String requestId = "audit-test-req-001";
        mvc.perform(post("/api/v1/auth/google").header("X-Request-Id", requestId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("idToken",
                                FakeGoogle.token().subject("audit-sub").email("audit@example.com").build()))))
                .andExpect(status().isOk());

        var types = authJdbcClient.sql("""
                        SELECT event_type FROM audit_events
                         WHERE request_id = :rid AND masked_email = 'a***@example.com'
                         ORDER BY id""")
                .param("rid", requestId)
                .query(String.class).list();
        assertThat(types).containsExactly("USER_REGISTERED", "ACCOUNT_LINKED", "LOGIN_SUCCEEDED");
    }

    private String userIdOf(JsonNode tokens) throws Exception {
        String response = mvc.perform(get("/api/v1/home")
                        .header("Authorization", "Bearer " + tokens.get("accessToken").asText()))
                .andExpect(jsonPath("$.message").value("Hello World"))
                .andReturn().getResponse().getContentAsString();
        return json.readTree(response).get("userId").asText();
    }

    private ResultActions postJson(String path, Map<String, String> body) throws Exception {
        return mvc.perform(post(path).contentType(MediaType.APPLICATION_JSON).content(json.writeValueAsString(body)));
    }

    private JsonNode body(ResultActions result) throws Exception {
        return json.readTree(result.andReturn().getResponse().getContentAsString());
    }
}
