package ru.edu.infoguard.server.api;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import ru.edu.infoguard.server.api.dto.ClientBootstrapResponse;
import ru.edu.infoguard.server.domain.UserEntity;
import ru.edu.infoguard.server.service.LicenseManagementService;
import ru.edu.infoguard.server.service.UserManagementService;

@RestController
@RequestMapping("/api/client")
public class ClientBootstrapController {

    private final UserManagementService userManagementService;
    private final LicenseManagementService licenseManagementService;
    private final String apiBaseUrl;

    public ClientBootstrapController(
            UserManagementService userManagementService,
            LicenseManagementService licenseManagementService,
            @Value("${app.jwt.issuer}") String apiBaseUrl) {
        this.userManagementService = userManagementService;
        this.licenseManagementService = licenseManagementService;
        this.apiBaseUrl = apiBaseUrl;
    }

    @GetMapping("/bootstrap")
    public ClientBootstrapResponse bootstrap(JwtAuthenticationToken authentication) {
        final UserEntity user = userManagementService.requireByUsername(authentication.getName());
        return new ClientBootstrapResponse(
                userManagementService.toResponse(user),
                licenseManagementService.getLicensesForUser(user),
                apiBaseUrl,
                "Bearer");
    }
}
