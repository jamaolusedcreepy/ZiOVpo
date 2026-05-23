package ru.edu.infoguard.server.api.dto;

import java.time.Instant;

public record UserResponse(
        Long id,
        String username,
        String fullName,
        String role,
        boolean enabled,
        Instant createdAt) {
}
