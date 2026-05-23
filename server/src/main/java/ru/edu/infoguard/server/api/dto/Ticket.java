package ru.edu.infoguard.server.api.dto;

import java.time.Instant;

public record Ticket(
        Instant serverDate,
        long ticketLifetimeSeconds,
        Instant licenseActivatedAt,
        Instant licenseExpiresAt,
        long userId,
        String deviceId,
        boolean blocked) {
}
