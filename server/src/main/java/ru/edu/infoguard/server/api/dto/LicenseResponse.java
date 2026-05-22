package ru.edu.infoguard.server.api.dto;

import java.time.Instant;

public record LicenseResponse(
        Long id,
        Long userId,
        String licenseKey,
        long certificateNumber,
        boolean active,
        boolean blocked,
        String deviceId,
        Instant issuedAt,
        Instant activatedAt,
        int validityDays,
        Instant expiresAt) {
}
