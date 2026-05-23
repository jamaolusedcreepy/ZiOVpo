package ru.edu.infoguard.server.service;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import ru.edu.infoguard.server.api.dto.AuthResponse;
import ru.edu.infoguard.server.api.dto.LoginRequest;
import ru.edu.infoguard.server.domain.RefreshTokenEntity;
import ru.edu.infoguard.server.domain.UserEntity;
import ru.edu.infoguard.server.repository.RefreshTokenRepository;
import ru.edu.infoguard.server.security.JwtTokenService;
import ru.edu.infoguard.server.security.JwtTokenService.IssuedTokenPair;

@Service
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserManagementService userManagementService;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenService jwtTokenService;

    public AuthService(
            AuthenticationManager authenticationManager,
            UserManagementService userManagementService,
            RefreshTokenRepository refreshTokenRepository,
            JwtTokenService jwtTokenService) {
        this.authenticationManager = authenticationManager;
        this.userManagementService = userManagementService;
        this.refreshTokenRepository = refreshTokenRepository;
        this.jwtTokenService = jwtTokenService;
    }

    public AuthResponse login(LoginRequest request) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(request.username(), request.password()));
        } catch (BadCredentialsException exception) {
            throw new ResponseStatusException(UNAUTHORIZED, "Invalid username or password", exception);
        }

        final UserEntity user = userManagementService.requireByUsername(request.username());
        return issueTokensForUser(user);
    }

    @Transactional
    public AuthResponse refresh(String rawRefreshToken) {
        final Jwt jwt = jwtTokenService.decode(rawRefreshToken);
        final String refreshTokenId = jwtTokenService.requireRefreshTokenId(rawRefreshToken);
        final RefreshTokenEntity refreshToken = refreshTokenRepository.findByTokenId(refreshTokenId)
                .orElseThrow(() -> new ResponseStatusException(UNAUTHORIZED, "Refresh token is not recognized"));

        final OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
        if (!refreshToken.isActiveAt(now) || jwtTokenService.getExpiry(jwt).isBefore(now)) {
            throw new ResponseStatusException(UNAUTHORIZED, "Refresh token expired or revoked");
        }

        refreshToken.setRevokedAt(now);
        final UserEntity user = refreshToken.getUser();
        return issueTokensForUser(user);
    }

    @Transactional
    public void logout(String rawRefreshToken) {
        final String refreshTokenId = jwtTokenService.requireRefreshTokenId(rawRefreshToken);
        refreshTokenRepository.findByTokenId(refreshTokenId).ifPresent(token -> {
            token.setRevokedAt(OffsetDateTime.now(ZoneOffset.UTC));
        });
    }

    public AuthResponse currentUser(String username) {
        final UserEntity user = userManagementService.requireByUsername(username);
        return new AuthResponse(
                null,
                null,
                null,
                null,
                userManagementService.toResponse(user));
    }

    private AuthResponse issueTokensForUser(UserEntity user) {
        final IssuedTokenPair tokenPair = jwtTokenService.issueTokens(user);

        final RefreshTokenEntity refreshToken = new RefreshTokenEntity();
        refreshToken.setTokenId(tokenPair.refreshTokenId());
        refreshToken.setUser(user);
        refreshToken.setCreatedAt(OffsetDateTime.now(ZoneOffset.UTC));
        refreshToken.setExpiresAt(OffsetDateTime.ofInstant(tokenPair.refreshTokenExpiresAt(), ZoneOffset.UTC));
        refreshTokenRepository.save(refreshToken);
        refreshTokenRepository.deleteAllByExpiresAtBefore(OffsetDateTime.now(ZoneOffset.UTC));

        return new AuthResponse(
                tokenPair.accessToken(),
                tokenPair.accessTokenExpiresAt(),
                tokenPair.refreshToken(),
                tokenPair.refreshTokenExpiresAt(),
                userManagementService.toResponse(user));
    }
}
