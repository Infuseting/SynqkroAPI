package fr.synqkro.api.auth.service;

import fr.synqkro.api.auth.dto.request.LoginRequest;
import fr.synqkro.api.auth.dto.request.RegisterRequest;
import fr.synqkro.api.auth.dto.response.TokenResponse;
import fr.synqkro.api.common.entity.UserEntity;
import fr.synqkro.api.common.exception.ApiException;
import fr.synqkro.api.common.repository.UserRepository;
import fr.synqkro.api.common.util.SnowflakeIDGenerator;
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

    public void logout(HttpServletRequest httpRequest, HttpServletResponse response) {
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
    }

    public TokenResponse refresh(HttpServletRequest httpRequest, HttpServletResponse response) {
        String refreshToken = getRefreshToken(httpRequest);

        if (refreshToken == null || refreshToken.isBlank()) {
            throw new ApiException("REFRESH_TOKEN_MISSING", HttpStatus.UNAUTHORIZED);
        }

        return tokenService.rotateRefreshToken(refreshToken, httpRequest, response);
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
}