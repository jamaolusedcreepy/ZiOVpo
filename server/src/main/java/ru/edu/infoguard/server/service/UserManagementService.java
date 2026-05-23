package ru.edu.infoguard.server.service;

import static org.springframework.http.HttpStatus.CONFLICT;
import static org.springframework.http.HttpStatus.NOT_FOUND;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import ru.edu.infoguard.server.api.dto.CreateUserRequest;
import ru.edu.infoguard.server.api.dto.UserResponse;
import ru.edu.infoguard.server.config.LicenseProperties;
import ru.edu.infoguard.server.domain.UserEntity;
import ru.edu.infoguard.server.repository.UserRepository;

@Service
public class UserManagementService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final LicenseManagementService licenseManagementService;
    private final LicenseProperties licenseProperties;

    public UserManagementService(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            LicenseManagementService licenseManagementService,
            LicenseProperties licenseProperties) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.licenseManagementService = licenseManagementService;
        this.licenseProperties = licenseProperties;
    }

    @Transactional
    public UserResponse createUser(CreateUserRequest request) {
        return createUser(request, null);
    }

    @Transactional
    public UserResponse createUser(CreateUserRequest request, Long certificateOverride) {
        if (userRepository.existsByUsername(request.username())) {
            throw new ResponseStatusException(CONFLICT, "User already exists");
        }

        final UserEntity user = new UserEntity();
        user.setUsername(request.username());
        user.setPasswordHash(passwordEncoder.encode(request.password()));
        user.setFullName(request.fullName());
        user.setRole(request.role());
        user.setEnabled(true);
        user.setCreatedAt(OffsetDateTime.now(ZoneOffset.UTC));

        final UserEntity savedUser = userRepository.save(user);
        final long certificateNumber = certificateOverride != null
                ? certificateOverride
                : licenseProperties.certificateBase() + savedUser.getId();
        licenseManagementService.createLicenseForUser(savedUser, certificateNumber);

        return toResponse(savedUser);
    }

    public List<UserResponse> listUsers() {
        return userRepository.findAll().stream()
                .map(this::toResponse)
                .toList();
    }

    public UserEntity requireByUsername(String username) {
        return userRepository.findByUsername(username)
                .orElseThrow(() -> new ResponseStatusException(NOT_FOUND, "User not found"));
    }

    public UserResponse toResponse(UserEntity user) {
        return new UserResponse(
                user.getId(),
                user.getUsername(),
                user.getFullName(),
                user.getRole().name(),
                user.isEnabled(),
                user.getCreatedAt().toInstant());
    }
}
