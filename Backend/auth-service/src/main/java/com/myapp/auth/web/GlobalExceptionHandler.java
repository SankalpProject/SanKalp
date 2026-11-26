package com.myapp.auth.web;

import com.myapp.auth.domain.exception.AuthException;
import com.myapp.auth.domain.exception.ErrorCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.NonNull;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.List;

/**
 * Maps errors to RFC 7807 Problem Details with a stable {@code code} field.
 * Never returns stack traces, exception messages from libraries, or rejected input values.
 */
@RestControllerAdvice
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AuthException.class)
    ResponseEntity<ProblemDetail> handleAuth(AuthException ex) {
        HttpStatus status = statusFor(ex.code());
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, ex.getMessage());
        problem.setProperty("code", ex.code().name());

        ResponseEntity.BodyBuilder builder = ResponseEntity.status(status);
        ex.retryAfter().ifPresent(d -> {
            long seconds = Math.max(1, d.toSeconds() + (d.toMillisPart() > 0 ? 1 : 0));
            builder.header(HttpHeaders.RETRY_AFTER, String.valueOf(seconds));
            problem.setProperty("retryAfterSeconds", seconds);
        });
        return builder.body(problem);
    }

    @ExceptionHandler(Exception.class)
    ResponseEntity<ProblemDetail> handleUnexpected(Exception ex) {
        log.error("Unhandled error", ex);
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.INTERNAL_SERVER_ERROR, "Something went wrong.");
        problem.setProperty("code", "INTERNAL_ERROR");
        return ResponseEntity.internalServerError().body(problem);
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(@NonNull MethodArgumentNotValidException ex,
                                                                  @NonNull HttpHeaders headers,
                                                                  @NonNull HttpStatusCode status,
                                                                  @NonNull WebRequest request) {
        List<String> fields = ex.getBindingResult().getFieldErrors().stream()
                .map(e -> e.getField())
                .distinct()
                .toList();
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Request validation failed.");
        problem.setProperty("code", "VALIDATION_FAILED");
        problem.setProperty("fields", fields);
        return ResponseEntity.badRequest().body(problem);
    }

    private static HttpStatus statusFor(ErrorCode code) {
        return switch (code) {
            case INVALID_EMAIL -> HttpStatus.BAD_REQUEST;
            case OTP_INVALID, OTP_ATTEMPTS_EXCEEDED, INVALID_REFRESH_TOKEN,
                 INVALID_EXTERNAL_TOKEN, EXTERNAL_EMAIL_NOT_VERIFIED -> HttpStatus.UNAUTHORIZED;
            case OTP_RESEND_TOO_SOON, RATE_LIMITED -> HttpStatus.TOO_MANY_REQUESTS;
        };
    }
}
