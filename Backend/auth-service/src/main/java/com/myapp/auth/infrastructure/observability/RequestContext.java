package com.myapp.auth.infrastructure.observability;

import org.slf4j.MDC;

/** The current request's correlation id, shared by logs, audit rows and error responses. */
public final class RequestContext {

    /** Logging MDC key; also printed by the log pattern as [requestId]. */
    public static final String REQUEST_ID_KEY = "requestId";

    private RequestContext() {
    }

    /** The id set by RequestCorrelationFilter, or null outside an HTTP request (e.g. scheduled jobs). */
    public static String requestId() {
        return MDC.get(REQUEST_ID_KEY);
    }
}
