package ru.edu.infoguard.server.api.dto;

import jakarta.validation.constraints.Positive;

public record RenewLicenseRequest(@Positive int additionalDays) {
}
