package ru.edu.infoguard.server.api.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Positive;
import jakarta.validation.constraints.Size;

public record CreateLicenseRequest(
        @NotBlank @Size(max = 64) String username,
        @Positive Integer validDays) {
}
