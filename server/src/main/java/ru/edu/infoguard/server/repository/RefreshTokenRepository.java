package ru.edu.infoguard.server.repository;

import java.time.OffsetDateTime;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import ru.edu.infoguard.server.domain.RefreshTokenEntity;

public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, Long> {
    Optional<RefreshTokenEntity> findByTokenId(String tokenId);

    void deleteAllByExpiresAtBefore(OffsetDateTime threshold);
}
