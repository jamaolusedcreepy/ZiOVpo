package ru.edu.infoguard.server.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ActivateLicenseRequest(
        @NotBlank @Size(max = 128) String licenseKey,
        @NotBlank @Size(max = 128) String deviceId) {
}
