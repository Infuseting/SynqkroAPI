package fr.synqkro.api.auth.service;

import fr.synqkro.api.auth.dto.request.LoginRequest;
import fr.synqkro.api.auth.dto.request.RegisterRequest;
import fr.synqkro.api.auth.dto.response.TokenResponse;
import fr.synqkro.api.common.entity.UserEntity;
import fr.synqkro.api.common.exception.ApiException;
import fr.synqkro.api.common.repository.UserRepository;
import fr.synqkro.api.common.util.SnowflakeIDGenerator;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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

    public void logout(String refreshToken) {
        tokenService.revokeRefreshToken(refreshToken);
    }
}