package com.myapp.auth.config;

import com.myapp.auth.infrastructure.persistence.InMemoryRefreshTokenStore;
import com.myapp.auth.infrastructure.persistence.InMemoryUserRepository;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Clock;

/**
 * In-memory persistence for fast automated tests ({@code auth.persistence=memory}).
 * Data is lost on restart: never use it for a deployed environment.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnProperty(name = "auth.persistence", havingValue = "memory")
public class InMemoryPersistenceConfig {

    @Bean
    InMemoryUserRepository userRepository() {
        return new InMemoryUserRepository();
    }

    @Bean
    InMemoryRefreshTokenStore refreshTokenStore(Clock clock) {
        return new InMemoryRefreshTokenStore(clock);
    }
}
