package ru.edu.infoguard.server.api;

import java.util.List;

import jakarta.validation.Valid;

import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import ru.edu.infoguard.server.api.dto.ActivateLicenseRequest;
import ru.edu.infoguard.server.api.dto.LicenseResponse;
import ru.edu.infoguard.server.api.dto.TicketResponse;
import ru.edu.infoguard.server.domain.UserEntity;
import ru.edu.infoguard.server.service.LicenseManagementService;
import ru.edu.infoguard.server.service.UserManagementService;

@Validated
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

    @GetMapping("/current")
    public TicketResponse getCurrentLicense(
            JwtAuthenticationToken authentication,
            @RequestParam String deviceId) {
        final UserEntity user = userManagementService.requireByUsername(authentication.getName());
        return licenseManagementService.getCurrentTicketForUser(user, deviceId);
    }

    @PostMapping("/activate")
    public TicketResponse activateLicense(
            JwtAuthenticationToken authentication,
            @Valid @RequestBody ActivateLicenseRequest request) {
        final UserEntity user = userManagementService.requireByUsername(authentication.getName());
        return licenseManagementService.activateLicense(user, request.licenseKey(), request.deviceId());
    }
}
