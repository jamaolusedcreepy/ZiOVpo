package ru.edu.infoguard.server.api.dto;

import java.util.List;

public record ClientBootstrapResponse(
        UserResponse user,
        List<LicenseResponse> licenses,
        String apiBaseUrl,
        String tokenType) {
}
