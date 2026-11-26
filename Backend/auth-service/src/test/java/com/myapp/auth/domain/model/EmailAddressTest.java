package com.myapp.auth.domain.model;

import com.myapp.auth.domain.exception.AuthException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullSource;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EmailAddressTest {

    @Test
    void normalisesAndMasks() {
        EmailAddress email = EmailAddress.of("  Satyam.B+test@Gmail.COM ");
        assertThat(email.value()).isEqualTo("satyam.b+test@gmail.com");
        assertThat(email.toString()).isEqualTo("s***@gmail.com").doesNotContain("satyam");
    }

    @ParameterizedTest
    @NullSource
    @ValueSource(strings = {"", "plain", "a@b", "@gmail.com", "a@@b.com", "a b@c.com", "a@-bad.com",
            "<script>@x.com", "a@b.c\nom","a@b.com;rm"})
    void rejectsInvalid(String raw) {
        assertThatThrownBy(() -> EmailAddress.of(raw)).isInstanceOf(AuthException.class);
    }

    @Test
    void rejectsOverlongAddress() {
        assertThatThrownBy(() -> EmailAddress.of("a".repeat(64) + "@" + "b".repeat(200) + ".com"))
                .isInstanceOf(AuthException.class);
    }
}
