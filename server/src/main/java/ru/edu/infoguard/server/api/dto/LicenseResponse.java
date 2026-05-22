package ru.edu.infoguard.server.api.dto;

import java.time.Instant;

public record LicenseResponse(
        String licenseKey,
        long certificateNumber,
        boolean active,
        Instant issuedAt,
        Instant expiresAt) {
}
