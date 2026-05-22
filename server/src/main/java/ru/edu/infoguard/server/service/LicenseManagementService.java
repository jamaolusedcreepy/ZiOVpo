package ru.edu.infoguard.server.service;

import java.security.SecureRandom;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;

import org.springframework.stereotype.Service;

import ru.edu.infoguard.server.api.dto.LicenseResponse;
import ru.edu.infoguard.server.config.LicenseProperties;
import ru.edu.infoguard.server.domain.LicenseEntity;
import ru.edu.infoguard.server.domain.UserEntity;
import ru.edu.infoguard.server.repository.LicenseRepository;

@Service
public class LicenseManagementService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final LicenseRepository licenseRepository;
    private final LicenseProperties licenseProperties;

    public LicenseManagementService(LicenseRepository licenseRepository, LicenseProperties licenseProperties) {
        this.licenseRepository = licenseRepository;
        this.licenseProperties = licenseProperties;
    }

    public LicenseEntity createLicenseForUser(UserEntity user, long certificateNumber) {
        final OffsetDateTime issuedAt = OffsetDateTime.now(ZoneOffset.UTC);
        final LicenseEntity license = new LicenseEntity();
        license.setUser(user);
        license.setLicenseKey(buildLicenseKey(certificateNumber));
        license.setCertificateNumber(certificateNumber);
        license.setIssuedAt(issuedAt);
        license.setExpiresAt(issuedAt.plusDays(licenseProperties.defaultValidDays()));
        license.setActive(true);
        return licenseRepository.save(license);
    }

    public List<LicenseResponse> getLicensesForUser(UserEntity user) {
        return licenseRepository.findAllByUserIdOrderByIssuedAtDesc(user.getId()).stream()
                .map(this::toResponse)
                .toList();
    }

    public LicenseResponse toResponse(LicenseEntity license) {
        return new LicenseResponse(
                license.getLicenseKey(),
                license.getCertificateNumber(),
                license.isActive(),
                license.getIssuedAt().toInstant(),
                license.getExpiresAt() == null ? null : license.getExpiresAt().toInstant());
    }

    private String buildLicenseKey(long certificateNumber) {
        final byte[] buffer = new byte[6];
        RANDOM.nextBytes(buffer);
        return "LIC-" + certificateNumber + "-" + HexFormat.of().withUpperCase().formatHex(buffer);
    }
}
