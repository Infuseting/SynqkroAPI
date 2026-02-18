package fr.synqkro.api.auth.service;

import fr.synqkro.api.common.entity.RefreshTokenEntity;
import fr.synqkro.api.common.entity.SessionEntity;
import fr.synqkro.api.common.entity.TrustedDeviceEntity;
import fr.synqkro.api.common.exception.ApiException;
import fr.synqkro.api.common.repository.RefreshTokenRepository;
import fr.synqkro.api.common.repository.SessionRepository;
import fr.synqkro.api.common.service.FingerprintService;
import fr.synqkro.api.common.service.TrustedDeviceService;
import fr.synqkro.api.common.util.SnowflakeIDGenerator;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

/**
 * Service pour la gestion des sessions utilisateur.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SessionService {

    private final SessionRepository sessionRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final TrustedDeviceService trustedDeviceService;
    private final FingerprintService fingerprintService;
    private final SnowflakeIDGenerator snowflake;

    /**
     * Crée une nouvelle session lors du login.
     */
    @Transactional
    public SessionEntity createSession(
            Long userId,
            Long refreshTokenId,
            HttpServletRequest request,
            String advancedFingerprint) {
        String fingerprint = fingerprintService.calculateFingerprint(request);
        String ip = fingerprintService.extractClientIp(request);
        String userAgent = request.getHeader("User-Agent");
        String countryCode = extractCountry(request);
        String city = extractCity(request);

        // Vérifier si device trusted
        TrustedDeviceEntity trustedDevice = null;
        if (advancedFingerprint != null) {
            if (trustedDeviceService.isTrusted(userId, advancedFingerprint)) {
                trustedDevice = trustedDeviceService.findOrCreate(userId, advancedFingerprint);
            }
        }

        SessionEntity session = SessionEntity.builder()
                .id(snowflake.nextId())
                .userId(userId)
                .refreshTokenId(refreshTokenId)
                .trustedDeviceId(trustedDevice != null ? trustedDevice.getId() : null)
                .fingerprint(fingerprint)
                .advancedFingerprint(advancedFingerprint)
                .ip(ip)
                .userAgent(userAgent)
                .countryCode(countryCode)
                .city(city)
                .riskScore(0)
                .build();

        SessionEntity saved = sessionRepository.save(session);

        log.info("Session created for user {}: session={}, trusted={}",
                userId, saved.getId(), trustedDevice != null);

        return saved;
    }

    /**
     * Liste toutes les sessions actives d'un utilisateur.
     */
    public List<SessionEntity> listSessions(Long userId) {
        return sessionRepository.findAllActiveByUserId(userId);
    }

    /**
     * Révoque une session spécifique.
     */
    @Transactional
    public void revokeSession(Long userId, Long sessionId) {
        SessionEntity session = sessionRepository.findById(sessionId)
                .orElseThrow(() -> new ApiException("SESSION_NOT_FOUND", HttpStatus.NOT_FOUND));

        if (!session.getUserId().equals(userId)) {
            throw new ApiException("FORBIDDEN", HttpStatus.FORBIDDEN);
        }

        // Supprimer session + refresh token associé
        refreshTokenRepository.deleteById(session.getRefreshTokenId());
        sessionRepository.delete(session);

        log.info("Session {} revoked by user {}", sessionId, userId);
    }

    /**
     * Révoque toutes les sessions d'un utilisateur.
     */
    @Transactional
    public void revokeAllSessions(Long userId, boolean keepCurrent, Long currentSessionId) {
        List<SessionEntity> sessions = sessionRepository.findAllActiveByUserId(userId);

        for (SessionEntity session : sessions) {
            if (keepCurrent && session.getId().equals(currentSessionId)) {
                continue;
            }

            refreshTokenRepository.deleteById(session.getRefreshTokenId());
            sessionRepository.delete(session);
        }

        log.info("All sessions revoked for user {} (kept current: {})", userId, keepCurrent);
    }

    /**
     * Met à jour le lastSeenAt d'une session.
     */
    @Transactional
    public void updateLastSeen(Long sessionId) {
        sessionRepository.findById(sessionId).ifPresent(session -> {
            session.setLastSeenAt(java.time.Instant.now());
            sessionRepository.save(session);
        });
    }

    /**
     * Récupère une session par refresh token ID.
     */
    public SessionEntity getByRefreshTokenId(Long refreshTokenId) {
        return sessionRepository.findByRefreshTokenId(refreshTokenId)
                .orElse(null);
    }

    /**
     * Helper pour extraire le pays.
     */
    private String extractCountry(HttpServletRequest request) {
        String country = request.getHeader("X-Country-Code");
        if (country == null) {
            country = request.getHeader("CF-IPCountry");
        }
        return country;
    }

    /**
     * Helper pour extraire la ville.
     */
    private String extractCity(HttpServletRequest request) {
        String city = request.getHeader("X-City");
        if (city == null) {
            city = request.getHeader("CF-IPCity");
        }
        return city;
    }
}
