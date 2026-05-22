package ru.edu.infoguard.server.security;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import static org.springframework.http.HttpStatus.UNAUTHORIZED;

import ru.edu.infoguard.server.config.JwtProperties;
import ru.edu.infoguard.server.domain.UserEntity;

@Service
public class JwtTokenService {

    public record IssuedTokenPair(
            String accessToken,
            Instant accessTokenExpiresAt,
            String refreshToken,
            String refreshTokenId,
            Instant refreshTokenExpiresAt) {
    }

    private static final String CLAIM_ROLE = "role";
    private static final String CLAIM_TOKEN_TYPE = "token_type";
    private static final String ACCESS_TOKEN_TYPE = "access";
    private static final String REFRESH_TOKEN_TYPE = "refresh";

    private final JwtEncoder jwtEncoder;
    private final JwtDecoder jwtDecoder;
    private final JwtProperties jwtProperties;

    public JwtTokenService(JwtEncoder jwtEncoder, JwtDecoder jwtDecoder, JwtProperties jwtProperties) {
        this.jwtEncoder = jwtEncoder;
        this.jwtDecoder = jwtDecoder;
        this.jwtProperties = jwtProperties;
    }

    public IssuedTokenPair issueTokens(UserEntity user) {
        final Instant issuedAt = Instant.now();
        final Instant accessExpiresAt = issuedAt.plus(jwtProperties.accessTtl());
        final Instant refreshExpiresAt = issuedAt.plus(jwtProperties.refreshTtl());
        final String refreshTokenId = UUID.randomUUID().toString();

        final String accessToken = encodeToken(user, ACCESS_TOKEN_TYPE, UUID.randomUUID().toString(), issuedAt, accessExpiresAt);
        final String refreshToken = encodeToken(user, REFRESH_TOKEN_TYPE, refreshTokenId, issuedAt, refreshExpiresAt);

        return new IssuedTokenPair(accessToken, accessExpiresAt, refreshToken, refreshTokenId, refreshExpiresAt);
    }

    public Jwt decode(String token) {
        try {
            return jwtDecoder.decode(token);
        } catch (Exception exception) {
            throw new ResponseStatusException(UNAUTHORIZED, "Invalid JWT token", exception);
        }
    }

    public String requireRefreshTokenId(String rawToken) {
        final Jwt jwt = decode(rawToken);
        ensureTokenType(jwt, REFRESH_TOKEN_TYPE);
        return jwt.getId();
    }

    public void ensureAccessToken(Jwt jwt) {
        ensureTokenType(jwt, ACCESS_TOKEN_TYPE);
    }

    public String getUsername(Jwt jwt) {
        return jwt.getSubject();
    }

    public OffsetDateTime getExpiry(Jwt jwt) {
        return OffsetDateTime.ofInstant(jwt.getExpiresAt(), ZoneOffset.UTC);
    }

    private void ensureTokenType(Jwt jwt, String expectedType) {
        final String actualType = jwt.getClaimAsString(CLAIM_TOKEN_TYPE);
        if (!expectedType.equals(actualType)) {
            throw new ResponseStatusException(UNAUTHORIZED, "Unexpected token type");
        }
    }

    private String encodeToken(
            UserEntity user,
            String tokenType,
            String tokenId,
            Instant issuedAt,
            Instant expiresAt) {
        final JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer(jwtProperties.issuer())
                .subject(user.getUsername())
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .id(tokenId)
                .claim(CLAIM_ROLE, user.getRole().name())
                .claim(CLAIM_TOKEN_TYPE, tokenType)
                .build();

        final JwsHeader header = JwsHeader.with(MacAlgorithm.HS256).build();
        return jwtEncoder.encode(JwtEncoderParameters.from(header, claims)).getTokenValue();
    }
}
