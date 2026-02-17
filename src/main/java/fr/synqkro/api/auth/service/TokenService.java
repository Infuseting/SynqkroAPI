package fr.synqkro.api.auth.service;

import fr.synqkro.api.auth.dto.internal.TokenValidation;
import fr.synqkro.api.auth.dto.response.TokenResponse;
import fr.synqkro.api.common.entity.RefreshTokenEntity;
import fr.synqkro.api.common.entity.UserEntity;
import fr.synqkro.api.common.event.SessionAnomalyEvent;
import fr.synqkro.api.common.event.TokenRevokedEvent;
import fr.synqkro.api.common.event.TokensRevokedAllEvent;
import fr.synqkro.api.common.exception.ApiException;
import fr.synqkro.api.common.producer.EventProducer;
import fr.synqkro.api.common.provider.JwtTokenProvider;
import fr.synqkro.api.common.repository.RefreshTokenRepository;
import fr.synqkro.api.common.repository.UserRepository;
import fr.synqkro.api.common.util.SnowflakeIDGenerator;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.digest.DigestUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.RedisCallback;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Set;

@Service
@RequiredArgsConstructor
@Slf4j
public class TokenService {

    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;
    private final UserRepository userRepository;
    private final RedisTemplate<String, String> redisTemplate;
    private final EventProducer eventProducer;
    private final SnowflakeIDGenerator snowflake;

    @Value("${security.jwt.refresh-token-expiry}")
    private long refreshTokenExpirySeconds;


    private String keyHash(String hashedToken) {
        return "rt:hash:" + hashedToken;
    }

    private String keyUserSet(long userId) {
        return "rt:user:" + userId;
    }


    public TokenResponse issueTokens(UserEntity user, HttpServletResponse response) {
        String accessToken  = jwtTokenProvider.generateAccessToken(user);
        String rawToken     = generateOpaqueToken();

        persistRefreshToken(user, rawToken);
        injectRefreshTokenCookie(response, rawToken);

        return new TokenResponse(
                accessToken,
                "Bearer",
                jwtTokenProvider.getAccessTokenExpiry()
        );
    }


    private void persistRefreshToken(UserEntity user, String rawToken) {
        String hashedToken = hashToken(rawToken);
        long tokenId = snowflake.nextId();
        long userId = user.getId();
        Duration ttl = Duration.ofSeconds(refreshTokenExpirySeconds);

        redisTemplate.executePipelined((RedisCallback<?>) connection -> {
            byte[] hashKey = keyHash(hashedToken).getBytes();
            byte[] userSetKey = keyUserSet(userId).getBytes();
            byte[] value = (userId + ":" + tokenId).getBytes();
            byte[] member = (hashedToken + ":" + tokenId).getBytes();
            long ttlSeconds = refreshTokenExpirySeconds;

            connection.stringCommands().setEx(hashKey, ttlSeconds, value);

            connection.setCommands().sAdd(userSetKey, member);
            connection.keyCommands().expire(userSetKey, ttlSeconds);

            return null;
        });
        refreshTokenRepository.save(RefreshTokenEntity.builder()
                .id(tokenId)
                .userId(userId)
                .tokenHash(hashedToken)
                .expiresAt(Instant.now().plusSeconds(refreshTokenExpirySeconds))
                .createdAt(Instant.now())
                .build());
    }

    @Transactional
    public TokenResponse rotateRefreshToken(String rawToken,
                                            HttpServletRequest request,
                                            HttpServletResponse response) {
        String hashedToken = hashToken(rawToken);


        String entry = Optional.ofNullable(
                redisTemplate.opsForValue().get(keyHash(hashedToken))
        ).orElseThrow(() ->
                new ApiException("REFRESH_TOKEN_INVALID", HttpStatus.UNAUTHORIZED)
        );

        long userId  = Long.parseLong(entry.split(":")[0]);
        long tokenId = Long.parseLong(entry.split(":")[1]);


        RefreshTokenEntity stored = refreshTokenRepository
                .findById(tokenId)
                .orElseThrow(() ->
                        new ApiException("REFRESH_TOKEN_INVALID", HttpStatus.UNAUTHORIZED)
                );

        checkSessionCoherence(stored, request, userId);


        revokeOne(hashedToken, userId, tokenId);

        UserEntity user = userRepository.findById(userId).orElseThrow(() ->
            new ApiException("USER_NOT_FOUND", HttpStatus.UNAUTHORIZED)
        );

        return issueTokens(user, response);
    }
    public TokenValidation validateRefreshToken(String rawToken) {
        String hashedToken = hashToken(rawToken);
        String entry = redisTemplate.opsForValue().get(keyHash(hashedToken));

        if (entry == null) {
            throw new ApiException("REFRESH_TOKEN_INVALID", HttpStatus.UNAUTHORIZED);
        }

        String[] parts  = entry.split(":");
        long userId     = Long.parseLong(parts[0]);
        long tokenId    = Long.parseLong(parts[1]);

        return new TokenValidation(userId, tokenId, hashedToken);
    }

    public void revokeRefreshToken(String rawToken) {
        String hashedToken = hashToken(rawToken);

        String entry = redisTemplate.opsForValue().get(keyHash(hashedToken));
        if (entry == null) return;

        long userId  = Long.parseLong(entry.split(":")[0]);
        long tokenId = Long.parseLong(entry.split(":")[1]);

        revokeOne(hashedToken, userId, tokenId);
    }

    private void revokeOne(String hashedToken, long userId, long tokenId) {
        redisTemplate.executePipelined((RedisCallback<?>) connection -> {
            connection.del(keyHash(hashedToken).getBytes());
            String member = hashedToken + ":" + tokenId;
            connection.setCommands().sRem(
                    keyUserSet(userId).getBytes(),
                    member.getBytes()
            );
            return null;
        });
        eventProducer.publish("token.revoked", new TokenRevokedEvent(tokenId, Instant.now()));
    }



    public void revokeAllTokensForUser(long userId) {
        String userSetKey = keyUserSet(userId);

        Set<String> members = redisTemplate.opsForSet().members(userSetKey);

        if (members == null || members.isEmpty()) return;

        redisTemplate.executePipelined((RedisCallback<?>) connection -> {
            for (String member : members) {
                String hash = member.split(":")[0];
                connection.del(keyHash(hash).getBytes());
            }
            connection.del(userSetKey.getBytes());
            return null;
        });
        List<Long> tokenIds = members.stream()
                .map(m -> Long.parseLong(m.split(":")[1]))
                .toList();

        eventProducer.publish("tokens.revoked-all",
                new TokensRevokedAllEvent(userId, tokenIds, Instant.now()));

        log.info("All tokens revoked — userId={} count={}", userId, members.size());
    }

    private void checkSessionCoherence(RefreshTokenEntity stored,
                                       HttpServletRequest request,
                                       long userId) {
        String incoming = buildFingerprint(request);
        String stored_fp = stored.getFingerprint();

        if (stored_fp == null) {
            stored.setFingerprint(incoming);
            refreshTokenRepository.save(stored);
            return;
        }

        if (!incoming.equals(stored_fp)) {
            log.warn("Token coherence failure — userId={}", userId);

            revokeAllTokensForUser(userId);

            eventProducer.publish("session.anomaly", new SessionAnomalyEvent(
                    userId,
                    stored.getIp(),
                    extractIp(request),
                    stored.getUserAgent(),
                    request.getHeader("User-Agent")
            ));

            throw new ApiException("SESSION_ANOMALY_DETECTED", HttpStatus.UNAUTHORIZED);
        }
    }

    private String buildFingerprint(HttpServletRequest request) {
        String subnet    = toSubnet(extractIp(request));
        String userAgent = request.getHeader("User-Agent");
        String locale    = request.getHeader("Accept-Language");
        return DigestUtils.sha256Hex(subnet + "|" + userAgent + "|" + locale);
    }

    private String toSubnet(String ip) {
        int lastDot = ip.lastIndexOf('.');
        return lastDot > 0 ? ip.substring(0, lastDot) : ip;
    }

    private String extractIp(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }


    private String generateOpaqueToken() {
        byte[] bytes = new byte[64];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String hashToken(String rawToken) {
        return DigestUtils.sha256Hex(rawToken);
    }


    private void injectRefreshTokenCookie(HttpServletResponse response, String rawToken) {
        ResponseCookie cookie = ResponseCookie.from("refreshToken", rawToken)
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/auth/refresh")
                .maxAge(refreshTokenExpirySeconds)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }
}