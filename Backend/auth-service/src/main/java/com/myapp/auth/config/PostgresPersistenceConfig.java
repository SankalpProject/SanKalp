package com.myapp.auth.config;

import com.myapp.auth.infrastructure.persistence.jdbc.JdbcAuditLog;
import com.myapp.auth.infrastructure.persistence.jdbc.JdbcRefreshTokenStore;
import com.myapp.auth.infrastructure.persistence.jdbc.JdbcUserRepository;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.simple.JdbcClient;

import javax.sql.DataSource;
import java.time.Clock;

/**
 * Default persistence: PostgreSQL. The DataSource (HikariCP pool) and Flyway migrations are
 * auto-configured by Spring Boot from {@code spring.datasource.*} / {@code spring.flyway.*}.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "auth.persistence", havingValue = "postgres", matchIfMissing = true)
public class PostgresPersistenceConfig {

    @Bean
    JdbcClient authJdbcClient(DataSource dataSource) {
        return JdbcClient.create(dataSource);
    }

    @Bean
    JdbcUserRepository userRepository(JdbcClient authJdbcClient) {
        return new JdbcUserRepository(authJdbcClient);
    }

    @Bean
    JdbcRefreshTokenStore refreshTokenStore(JdbcClient authJdbcClient, Clock clock) {
        return new JdbcRefreshTokenStore(authJdbcClient, clock);
    }

    /** Durable audit sink; ApplicationConfig adds it to the CompositeAuditLog. */
    @Bean
    JdbcAuditLog jdbcAuditLog(JdbcClient authJdbcClient, Clock clock, AuthProperties props) {
        return new JdbcAuditLog(authJdbcClient, clock, props.audit().retentionDays());
    }
}
