package com.myapp.auth.config;

import com.myapp.auth.web.security.ProblemJsonAuthenticationEntryPoint;
import jakarta.servlet.DispatcherType;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;

/**
 * Stateless API security:
 * <ul>
 *   <li>Bearer JWT on every non-public endpoint (deny by default);</li>
 *   <li>no server session, no cookies → CSRF protection is not applicable and is disabled;</li>
 *   <li>no CORS configuration → browsers on other origins are blocked (native apps are unaffected);</li>
 *   <li>hardened response headers.</li>
 * </ul>
 */
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    @Bean
    SecurityFilterChain apiSecurity(HttpSecurity http, ProblemJsonAuthenticationEntryPoint entryPoint,
                                    Environment environment) throws Exception {
        boolean managementIsolated = isManagementPortIsolated(environment);
        http
                .csrf(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable)
                .formLogin(AbstractHttpConfigurer::disable)
                .logout(AbstractHttpConfigurer::disable)
                .requestCache(AbstractHttpConfigurer::disable)
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> {
                    auth.dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                            .requestMatchers(HttpMethod.POST,
                                    "/api/v1/auth/otp/request",
                                    "/api/v1/auth/otp/verify",
                                    "/api/v1/auth/google",
                                    "/api/v1/auth/token/refresh",
                                    "/api/v1/auth/logout").permitAll()
                            // Health (liveness/readiness) is safe to expose: no details, just UP/DOWN.
                            .requestMatchers(EndpointRequest.to(HealthEndpoint.class)).permitAll();
                    // Metrics reveal internals: allowed ONLY on the isolated internal management port.
                    // If someone puts management on the public port, fail closed instead of leaking.
                    if (managementIsolated) {
                        auth.requestMatchers(EndpointRequest.toAnyEndpoint()).permitAll();
                    } else {
                        auth.requestMatchers(EndpointRequest.toAnyEndpoint()).denyAll();
                    }
                    auth.anyRequest().authenticated();
                })
                .oauth2ResourceServer(rs -> rs
                        .jwt(Customizer.withDefaults())
                        .authenticationEntryPoint(entryPoint))
                .exceptionHandling(ex -> ex.authenticationEntryPoint(entryPoint))
                .headers(h -> h
                        .contentSecurityPolicy(csp -> csp.policyDirectives("default-src 'none'; frame-ancestors 'none'"))
                        .frameOptions(f -> f.deny())
                        .httpStrictTransportSecurity(hsts -> hsts.includeSubDomains(true).maxAgeInSeconds(31_536_000))
                        .referrerPolicy(r -> r.policy(ReferrerPolicyHeaderWriter.ReferrerPolicy.NO_REFERRER)));
        return http.build();
    }

    /** True when actuator endpoints are served on their own port (not reachable through the public API port). */
    static boolean isManagementPortIsolated(Environment env) {
        Integer managementPort = env.getProperty("management.server.port", Integer.class);
        int serverPort = env.getProperty("server.port", Integer.class, 8080);
        return managementPort != null && managementPort > 0 && managementPort != serverPort;
    }
}
