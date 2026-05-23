package ru.edu.infoguard.server.service;

import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.NOT_FOUND;

import java.security.SecureRandom;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.HexFormat;
import java.util.List;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import ru.edu.infoguard.server.api.dto.LicenseResponse;
import ru.edu.infoguard.server.api.dto.Ticket;
import ru.edu.infoguard.server.api.dto.TicketResponse;
import ru.edu.infoguard.server.config.LicenseProperties;
import ru.edu.infoguard.server.domain.LicenseEntity;
import ru.edu.infoguard.server.domain.UserEntity;
import ru.edu.infoguard.server.repository.LicenseRepository;

@Service
public class LicenseManagementService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final LicenseRepository licenseRepository;
    private final LicenseProperties licenseProperties;
    private final TicketSignatureService ticketSignatureService;

    public LicenseManagementService(
            LicenseRepository licenseRepository,
            LicenseProperties licenseProperties,
            TicketSignatureService ticketSignatureService) {
        this.licenseRepository = licenseRepository;
        this.licenseProperties = licenseProperties;
        this.ticketSignatureService = ticketSignatureService;
    }

    @Transactional
    public LicenseEntity createLicenseForUser(UserEntity user, long certificateNumber) {
        return createLicenseForUser(user, certificateNumber, null);
    }

    @Transactional
    public LicenseEntity createLicenseForUser(UserEntity user, long certificateNumber, Integer validDaysOverride) {
        final OffsetDateTime issuedAt = OffsetDateTime.now(ZoneOffset.UTC);
        final LicenseEntity license = new LicenseEntity();
        license.setUser(user);
        license.setLicenseKey(buildLicenseKey(certificateNumber));
        license.setCertificateNumber(certificateNumber);
        license.setIssuedAt(issuedAt);
        license.setActivatedAt(null);
        license.setExpiresAt(null);
        license.setDeviceId(null);
        license.setBlocked(false);
        license.setValidityDays(validDaysOverride != null ? validDaysOverride : licenseProperties.defaultValidDays());
        license.setActive(false);
        return licenseRepository.save(license);
    }

    @Transactional(readOnly = true)
    public List<LicenseResponse> getLicensesForUser(UserEntity user) {
        return licenseRepository.findAllByUserIdOrderByIssuedAtDesc(user.getId()).stream()
                .map(this::toResponse)
                .toList();
    }

    @Transactional
    public TicketResponse activateLicense(UserEntity user, String licenseKey, String deviceId) {
        final LicenseEntity license = licenseRepository.findByLicenseKey(licenseKey)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "License key not found"));

        if (!license.getUser().getId().equals(user.getId())) {
            throw new ResponseStatusException(CONFLICT, "License key is bound to a different user");
        }

        if (license.isBlocked()) {
            throw new ResponseStatusException(CONFLICT, "License is blocked");
        }

        if (license.isActive()) {
            if (!deviceId.equals(license.getDeviceId())) {
                throw new ResponseStatusException(CONFLICT, "License is already activated on another device");
            }
            return toTicketResponse(license);
        }

        final OffsetDateTime activatedAt = OffsetDateTime.now(ZoneOffset.UTC);
        license.setActivatedAt(activatedAt);
        license.setExpiresAt(activatedAt.plusDays(license.getValidityDays()));
        license.setDeviceId(deviceId);
        license.setActive(true);
        return toTicketResponse(license);
    }

    @Transactional(readOnly = true)
    public TicketResponse getCurrentTicketForUser(UserEntity user, String deviceId) {
        final LicenseEntity license = licenseRepository
                .findFirstByUserIdAndActiveTrueAndDeviceIdOrderByActivatedAtDesc(user.getId(), deviceId)
                .orElseGet(() -> licenseRepository.findFirstByUserIdAndActiveTrueOrderByActivatedAtDesc(user.getId())
                        .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "No active license was found")));

        if (license.getDeviceId() == null || !license.getDeviceId().equals(deviceId)) {
            throw new ResponseStatusException(CONFLICT, "License is activated on another device");
        }

        if (license.getExpiresAt() == null || license.getExpiresAt().isBefore(OffsetDateTime.now(ZoneOffset.UTC))) {
            throw new ResponseStatusException(NOT_FOUND, "The active license has expired");
        }

        return toTicketResponse(license);
    }

    @Transactional
    public LicenseResponse renewLicense(long licenseId, int additionalDays) {
        final LicenseEntity license = licenseRepository.findById(licenseId)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "License not found"));

        license.setValidityDays(license.getValidityDays() + additionalDays);
        if (license.getExpiresAt() != null) {
            license.setExpiresAt(license.getExpiresAt().plusDays(additionalDays));
        }

        return toResponse(license);
    }

    public LicenseResponse toResponse(LicenseEntity license) {
        return new LicenseResponse(
                license.getId(),
                license.getUser().getId(),
                license.getLicenseKey(),
                license.getCertificateNumber(),
                license.isActive(),
                license.isBlocked(),
                license.getDeviceId(),
                license.getIssuedAt().toInstant(),
                license.getActivatedAt() == null ? null : license.getActivatedAt().toInstant(),
                license.getValidityDays(),
                license.getExpiresAt() == null ? null : license.getExpiresAt().toInstant());
    }

    public TicketResponse toTicketResponse(LicenseEntity license) {
        if (!license.isActive() || license.getActivatedAt() == null || license.getExpiresAt() == null || license.getDeviceId() == null) {
            throw new ResponseStatusException(CONFLICT, "License is not activated");
        }

        final Ticket ticket = new Ticket(
                OffsetDateTime.now(ZoneOffset.UTC).toInstant(),
                licenseProperties.ticketLifetime().toSeconds(),
                license.getActivatedAt().toInstant(),
                license.getExpiresAt().toInstant(),
                license.getUser().getId(),
                license.getDeviceId(),
                license.isBlocked());
        return new TicketResponse(ticket, ticketSignatureService.sign(ticket));
    }

    private String buildLicenseKey(long certificateNumber) {
        final byte[] buffer = new byte[6];
        RANDOM.nextBytes(buffer);
        return "LIC-" + certificateNumber + "-" + HexFormat.of().withUpperCase().formatHex(buffer);
    }
}
