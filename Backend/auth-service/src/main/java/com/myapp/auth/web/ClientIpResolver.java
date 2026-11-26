package com.myapp.auth.web;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.stereotype.Component;

/**
 * Resolves the caller IP used for rate limiting.
 * <p>
 * We deliberately use {@code getRemoteAddr()} and NOT a raw X-Forwarded-For header, which any client can forge
 * to bypass rate limits. When deployed behind a trusted load balancer, set
 * {@code server.forward-headers-strategy=native|framework} so the container rewrites remoteAddr from the
 * proxy's header — and make sure only the proxy can reach the service.
 */
@Component
public class ClientIpResolver {

    public String resolve(HttpServletRequest request) {
        return request.getRemoteAddr();
    }
}
