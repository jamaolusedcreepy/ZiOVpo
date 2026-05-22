package ru.edu.infoguard.server.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app.license")
public record LicenseProperties(
        long certificateBase,
        int defaultValidDays,
        Duration ticketLifetime,
        String ticketSignatureSecret) {
}
