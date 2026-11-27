package com.myapp.auth.web.observability;

import com.myapp.auth.infrastructure.observability.RequestContext;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Correlation + access log, first in the chain (before Spring Security, so 401/429s are covered too).
 * <ul>
 *   <li>Reuses the caller's {@code X-Request-Id} (e.g. from the mobile app or a gateway) only if it is a
 *       safe token; anything else is replaced, which prevents log injection via the header.</li>
 *   <li>Puts it in the logging MDC, so EVERY log line of the request carries {@code requestId}.</li>
 *   <li>Returns it in the response header (and error bodies) so a user report can be traced to log lines.</li>
 *   <li>Writes one ACCESS line per request: method, path, status, duration. Never query strings or bodies,
 *       which may contain personal data.</li>
 * </ul>
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class RequestCorrelationFilter extends OncePerRequestFilter {

    public static final String HEADER = "X-Request-Id";
    public static final String MDC_KEY = RequestContext.REQUEST_ID_KEY;

    private static final Pattern SAFE_ID = Pattern.compile("^[A-Za-z0-9._-]{8,64}$");
    private static final Logger access = LoggerFactory.getLogger("ACCESS");

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain chain) throws ServletException, IOException {
        String requestId = resolveRequestId(request.getHeader(HEADER));
        long start = System.nanoTime();
        MDC.put(MDC_KEY, requestId);
        response.setHeader(HEADER, requestId);
        try {
            chain.doFilter(request, response);
        } finally {
            long durationMs = (System.nanoTime() - start) / 1_000_000;
            access.atInfo()
                    .addKeyValue("http.method", request.getMethod())
                    .addKeyValue("http.path", request.getRequestURI())
                    .addKeyValue("http.status", response.getStatus())
                    .addKeyValue("duration_ms", durationMs)
                    .log("{} {} {} {}ms", request.getMethod(), request.getRequestURI(), response.getStatus(), durationMs);
            MDC.remove(MDC_KEY); // threads are pooled: never leak an id into the next request
        }
    }

    static String resolveRequestId(String incoming) {
        return incoming != null && SAFE_ID.matcher(incoming).matches() ? incoming : UUID.randomUUID().toString();
    }
}
