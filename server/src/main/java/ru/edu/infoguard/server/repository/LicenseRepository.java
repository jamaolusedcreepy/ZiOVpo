package ru.edu.infoguard.server.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import ru.edu.infoguard.server.domain.LicenseEntity;

public interface LicenseRepository extends JpaRepository<LicenseEntity, Long> {
    List<LicenseEntity> findAllByUserIdOrderByIssuedAtDesc(Long userId);
    Optional<LicenseEntity> findByLicenseKey(String licenseKey);
    Optional<LicenseEntity> findFirstByUserIdAndActiveTrueOrderByActivatedAtDesc(Long userId);
    Optional<LicenseEntity> findFirstByUserIdAndActiveTrueAndDeviceIdOrderByActivatedAtDesc(Long userId, String deviceId);
}
