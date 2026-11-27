package com.myapp.auth.infrastructure.observability;

import com.myapp.auth.application.port.out.AuditLog;
import com.myapp.auth.application.port.out.AuditLog.AuditEvent;
import com.myapp.auth.application.port.out.AuditLog.EventType;
import com.myapp.auth.domain.model.EmailAddress;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

class CompositeAuditLogTest {

    @Test
    void aFailingSinkNeverBreaksTheRequestAndOtherSinksStillReceiveTheEvent() {
        List<AuditEvent> received = new ArrayList<>();
        AuditLog broken = e -> { throw new IllegalStateException("SIEM down"); };
        AuditLog composite = new CompositeAuditLog(List.of(broken, received::add));

        assertThatCode(() -> composite.record(AuditEvent.of(EventType.LOGIN_SUCCEEDED))).doesNotThrowAnyException();
        assertThat(received).hasSize(1);
    }

    @Test
    void eventsOnlyEverHoldTheMaskedEmail() {
        AuditEvent event = AuditEvent.of(EventType.OTP_REQUESTED).email(EmailAddress.of("satyam@example.com"));
        assertThat(event.maskedEmail()).isEqualTo("s***@example.com");
        assertThat(event.toString()).doesNotContain("satyam");
    }
}
