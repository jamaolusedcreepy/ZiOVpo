package ru.edu.infoguard.server.api;

import jakarta.validation.Valid;

import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import ru.edu.infoguard.server.api.dto.CreateLicenseRequest;
import ru.edu.infoguard.server.api.dto.LicenseResponse;
import ru.edu.infoguard.server.api.dto.RenewLicenseRequest;
import ru.edu.infoguard.server.domain.UserEntity;
import ru.edu.infoguard.server.service.LicenseManagementService;
import ru.edu.infoguard.server.service.UserManagementService;

@Validated
@RestController
@RequestMapping("/api/admin/licenses")
public class AdminLicenseController {

    private final LicenseManagementService licenseManagementService;
    private final UserManagementService userManagementService;

    public AdminLicenseController(
            LicenseManagementService licenseManagementService,
            UserManagementService userManagementService) {
        this.licenseManagementService = licenseManagementService;
        this.userManagementService = userManagementService;
    }

    @PostMapping
    public LicenseResponse createLicense(@Valid @RequestBody CreateLicenseRequest request) {
        final UserEntity user = userManagementService.requireByUsername(request.username());
        return licenseManagementService.toResponse(
                licenseManagementService.createLicenseForUser(
                        user,
                        System.currentTimeMillis(),
                        request.validDays()));
    }

    @PostMapping("/{licenseId}/renew")
    public LicenseResponse renewLicense(
            @PathVariable long licenseId,
            @Valid @RequestBody RenewLicenseRequest request) {
        return licenseManagementService.renewLicense(licenseId, request.additionalDays());
    }
}
