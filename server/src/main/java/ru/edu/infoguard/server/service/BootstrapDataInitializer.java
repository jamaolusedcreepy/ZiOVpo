package ru.edu.infoguard.server.service;

import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.stereotype.Component;

import ru.edu.infoguard.server.api.dto.CreateUserRequest;
import ru.edu.infoguard.server.config.BootstrapAdminProperties;
import ru.edu.infoguard.server.config.LicenseProperties;
import ru.edu.infoguard.server.domain.AppRole;
import ru.edu.infoguard.server.repository.UserRepository;

@Component
public class BootstrapDataInitializer implements ApplicationRunner {

    private final BootstrapAdminProperties bootstrapAdminProperties;
    private final LicenseProperties licenseProperties;
    private final UserRepository userRepository;
    private final UserManagementService userManagementService;

    public BootstrapDataInitializer(
            BootstrapAdminProperties bootstrapAdminProperties,
            LicenseProperties licenseProperties,
            UserRepository userRepository,
            UserManagementService userManagementService) {
        this.bootstrapAdminProperties = bootstrapAdminProperties;
        this.licenseProperties = licenseProperties;
        this.userRepository = userRepository;
        this.userManagementService = userManagementService;
    }

    @Override
    public void run(ApplicationArguments args) {
        if (!bootstrapAdminProperties.enabled()) {
            return;
        }

        if (userRepository.existsByUsername(bootstrapAdminProperties.username())) {
            return;
        }

        final CreateUserRequest request = new CreateUserRequest(
                bootstrapAdminProperties.username(),
                bootstrapAdminProperties.password(),
                bootstrapAdminProperties.fullName(),
                AppRole.ADMIN);

        userManagementService.createUser(request, licenseProperties.certificateBase());
    }
}
