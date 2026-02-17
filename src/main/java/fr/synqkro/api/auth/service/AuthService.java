package fr.synqkro.api.auth.service;

import fr.synqkro.api.auth.dto.internal.TokenValidation;
import fr.synqkro.api.auth.dto.request.LoginRequest;
import fr.synqkro.api.auth.dto.request.RegisterRequest;
import fr.synqkro.api.auth.dto.response.DeleteResponse;
import fr.synqkro.api.auth.dto.response.LogoutResponse;
import fr.synqkro.api.auth.dto.response.TokenResponse;
import fr.synqkro.api.auth.dto.response.UserProfileResponse;
import fr.synqkro.api.common.entity.RefreshTokenEntity;
import fr.synqkro.api.common.entity.UserEntity;
import fr.synqkro.api.common.exception.ApiException;
import fr.synqkro.api.common.repository.RefreshTokenRepository;
import fr.synqkro.api.common.repository.UserRepository;
import fr.synqkro.api.common.util.SnowflakeIDGenerator;
import fr.synqkro.api.common.util.UserDataGenerator;
import fr.synqkro.api.common.provider.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;


@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;
    private final SnowflakeIDGenerator snowflake;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;

    @Transactional
    public TokenResponse register(RegisterRequest request, HttpServletResponse response) {

        if (userRepository.existsByEmail(request.email())) {
            throw new ApiException("EMAIL_ALREADY_USED", HttpStatus.CONFLICT);
        }
        if (userRepository.existsByUsername(request.username())) {
            throw new ApiException("USERNAME_ALREADY_TAKEN", HttpStatus.CONFLICT);
        }

        UserEntity user = UserEntity.builder()
                .id(snowflake.nextId())
                .username(request.username())
                .email(request.email())
                .passwordHash(passwordEncoder.encode(request.password()))
                .emailVerified(false)
                .createdAt(Instant.now())
                .build();

        userRepository.save(user);
        log.info("New user registered: id={}", user.getId());

        return tokenService.issueTokens(user, response);
    }

    @Transactional
    public TokenResponse login(LoginRequest request, HttpServletResponse response) {

        UserEntity user = userRepository
                .findByEmailOrUsername(request.usernameOrEmail())
                .orElseThrow(() -> new ApiException("INVALID_CREDENTIALS", HttpStatus.UNAUTHORIZED));

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new ApiException("INVALID_CREDENTIALS", HttpStatus.UNAUTHORIZED);
        }

        return tokenService.issueTokens(user, response);
    }

    @Transactional
    public LogoutResponse logout(HttpServletRequest httpRequest, HttpServletResponse response) {
        String refreshToken = getRefreshToken(httpRequest);

        if (refreshToken != null && !refreshToken.isBlank()) {
            tokenService.revokeRefreshToken(refreshToken);
        }
        ResponseCookie deleteCookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/auth/refresh")
                .maxAge(0)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, deleteCookie.toString());

        return new LogoutResponse();
    }
    @Transactional
    public TokenResponse refresh(HttpServletRequest httpRequest, HttpServletResponse response) {
        String refreshToken = getRefreshToken(httpRequest);

        if (refreshToken == null || refreshToken.isBlank()) {
            throw new ApiException("REFRESH_TOKEN_MISSING", HttpStatus.UNAUTHORIZED);
        }

        return tokenService.rotateRefreshToken(refreshToken, httpRequest, response);
    }
    @Transactional
    public DeleteResponse delete(HttpServletRequest httpRequest, HttpServletResponse response) {
        String refreshToken = getRefreshToken(httpRequest);
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new ApiException("REFRESH_TOKEN_MISSING", HttpStatus.UNAUTHORIZED);
        }

        TokenValidation validation = tokenService.validateRefreshToken(refreshToken);
        long userId = validation.userId();

        UserEntity userEntity = userRepository.findById(userId)
                .orElseThrow(() -> new ApiException("USER_NOT_FOUND", HttpStatus.NOT_FOUND));

        tokenService.revokeAllTokensForUser(userEntity.getId());

        String anonymousUsername = UserDataGenerator.generateRandomUsername();
        String anonymousEmail = UserDataGenerator.generateRandomEmail();
        String randomHash = passwordEncoder.encode(UserDataGenerator.generateRandomPassword());

        userRepository.anonymizeUser(userEntity.getId(), anonymousUsername, anonymousEmail, randomHash, Instant.now());

        ResponseCookie deleteCookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/auth/refresh")
                .maxAge(0)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, deleteCookie.toString());

        log.info("User delete: id={}", userEntity.getId());

        return new DeleteResponse();
    }

    public String getRefreshToken(HttpServletRequest httpRequest) {
        String refreshToken = null;

        Cookie[] cookies = httpRequest.getCookies();
        if (cookies != null) {
            for (Cookie c : cookies) {
                if ("refreshToken".equals(c.getName())) {
                    refreshToken = c.getValue();
                    break;
                }
            }
        }

        return refreshToken;
    }

    public UserProfileResponse getCurrentUser(HttpServletRequest request) {
        String authHeader = request.getHeader(org.springframework.http.HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new fr.synqkro.api.common.exception.ApiException("ACCESS_TOKEN_MISSING", org.springframework.http.HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7).trim();
        if (!jwtTokenProvider.validateToken(token)) {
            throw new fr.synqkro.api.common.exception.ApiException("ACCESS_TOKEN_INVALID", org.springframework.http.HttpStatus.UNAUTHORIZED);
        }

        io.jsonwebtoken.Claims claims = jwtTokenProvider.parseToken(token);
        long userId;
        try {
            userId = Long.parseLong(claims.getSubject());
        } catch (Exception ex) {
            throw new fr.synqkro.api.common.exception.ApiException("ACCESS_TOKEN_INVALID", org.springframework.http.HttpStatus.UNAUTHORIZED);
        }

        fr.synqkro.api.common.entity.UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new fr.synqkro.api.common.exception.ApiException("USER_NOT_FOUND", org.springframework.http.HttpStatus.NOT_FOUND));

        if (user.getStatus() != fr.synqkro.api.common.enums.UserStatus.ACTIVE) {
            throw new fr.synqkro.api.common.exception.ApiException("USER_FORBIDDEN", org.springframework.http.HttpStatus.FORBIDDEN);
        }

        return new UserProfileResponse(
                String.valueOf(user.getId()),
                user.getUsername(),
                user.getEmail(),
                user.getAvatarKey(),
                user.isEmailVerified(),
                user.getCreatedAt().toString()
        );
    }

}