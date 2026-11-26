package com.myapp.auth.domain.model;

import java.util.Objects;
import java.util.UUID;

/** Opaque user identifier. Random UUIDs avoid exposing sequential IDs (IDOR / enumeration). */
public record UserId(UUID value) {

    public UserId {
        Objects.requireNonNull(value, "value");
    }

    public static UserId newId() {
        return new UserId(UUID.randomUUID());
    }

    @Override
    public String toString() {
        return value.toString();
    }
}
