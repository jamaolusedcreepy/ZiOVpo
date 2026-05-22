package ru.edu.infoguard.server.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import ru.edu.infoguard.server.domain.UserEntity;

public interface UserRepository extends JpaRepository<UserEntity, Long> {
    Optional<UserEntity> findByUsername(String username);

    boolean existsByUsername(String username);
}
