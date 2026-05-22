package ru.edu.infoguard.server.api;

import java.util.List;

import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import ru.edu.infoguard.server.api.dto.LicenseResponse;
import ru.edu.infoguard.server.domain.UserEntity;
import ru.edu.infoguard.server.service.LicenseManagementService;
import ru.edu.infoguard.server.service.UserManagementService;

@RestController
@RequestMapping("/api/licenses")
public class LicenseController {

    private final UserManagementService userManagementService;
    private final LicenseManagementService licenseManagementService;

    public LicenseController(
            UserManagementService userManagementService,
            LicenseManagementService licenseManagementService) {
        this.userManagementService = userManagementService;
        this.licenseManagementService = licenseManagementService;
    }

    @GetMapping("/me")
    public List<LicenseResponse> getMyLicenses(JwtAuthenticationToken authentication) {
        final UserEntity user = userManagementService.requireByUsername(authentication.getName());
        return licenseManagementService.getLicensesForUser(user);
    }
}
