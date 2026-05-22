package ru.edu.infoguard.server.api;

import jakarta.validation.Valid;

import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import ru.edu.infoguard.server.api.dto.AuthResponse;
import ru.edu.infoguard.server.api.dto.LoginRequest;
import ru.edu.infoguard.server.api.dto.LogoutRequest;
import ru.edu.infoguard.server.api.dto.RefreshTokenRequest;
import ru.edu.infoguard.server.service.AuthService;

@Validated
@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    @PostMapping("/login")
    public AuthResponse login(@Valid @RequestBody LoginRequest request) {
        return authService.login(request);
    }

    @PostMapping("/refresh")
    public AuthResponse refresh(@Valid @RequestBody RefreshTokenRequest request) {
        return authService.refresh(request.refreshToken());
    }

    @PostMapping("/logout")
    public void logout(@Valid @RequestBody LogoutRequest request) {
        authService.logout(request.refreshToken());
    }

    @GetMapping("/me")
    public AuthResponse me(JwtAuthenticationToken authentication) {
        return authService.currentUser(authentication.getName());
    }
}
