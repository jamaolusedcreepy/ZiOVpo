package ru.edu.infoguard.server.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import ru.edu.infoguard.server.domain.LicenseEntity;

public interface LicenseRepository extends JpaRepository<LicenseEntity, Long> {
    List<LicenseEntity> findAllByUserIdOrderByIssuedAtDesc(Long userId);
}
