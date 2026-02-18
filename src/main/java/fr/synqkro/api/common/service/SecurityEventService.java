package fr.synqkro.api.common.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import fr.synqkro.api.common.entity.SecurityEventEntity;
import fr.synqkro.api.common.enums.SecurityEventType;
import fr.synqkro.api.common.repository.SecurityEventRepository;
import fr.synqkro.api.common.util.SnowflakeIDGenerator;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Service pour logger les événements de sécurité (audit trail complet).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SecurityEventService {

    private final SecurityEventRepository securityEventRepository;
    private final SnowflakeIDGenerator snowflake;
    private final FingerprintService fingerprintService;
    private final ObjectMapper objectMapper;

    /**
     * Enregistre un événement de sécurité.
     */
    @Transactional
    public SecurityEventEntity logEvent(
            Long userId,
            SecurityEventType type,
            HttpServletRequest request,
            Integer riskScore,
            Map<String, Object> additionalDetails) {
        String ip = fingerprintService.extractClientIp(request);
        String userAgent = request.getHeader("User-Agent");
        String countryCode = extractCountryFromRequest(request);
        String city = extractCityFromRequest(request);

        return logEvent(userId, type, ip, userAgent, countryCode, city, riskScore, additionalDetails);
    }

    /**
     * Enregistre un événement de sécurité avec toutes les données.
     */
    @Transactional
    public SecurityEventEntity logEvent(
            Long userId,
            SecurityEventType type,
            String ip,
            String userAgent,
            String countryCode,
            String city,
            Integer riskScore,
            Map<String, Object> additionalDetails) {
        SecurityEventEntity event = SecurityEventEntity.builder()
                .id(snowflake.nextId())
                .userId(userId)
                .type(type)
                .ip(ip)
                .userAgent(userAgent)
                .countryCode(countryCode)
                .city(city)
                .riskScore(riskScore)
                .details(serializeDetails(additionalDetails))
                .build();

        SecurityEventEntity saved = securityEventRepository.save(event);

        // Log critique si événement à haut risque
        if (saved.isHighRiskEvent()) {
            log.warn("High risk security event: type={}, userId={}, riskScore={}",
                    type, userId, riskScore);
        }

        return saved;
    }

    /**
     * Enregistre un événement simple sans détails.
     */
    @Transactional
    public SecurityEventEntity logEvent(Long userId, SecurityEventType type, HttpServletRequest request) {
        return logEvent(userId, type, request, null, null);
    }

    /**
     * Récupère l'historique des événements d'un utilisateur.
     */
    public Page<SecurityEventEntity> getUserEvents(Long userId, Pageable pageable) {
        return securityEventRepository.findByUserIdOrderByCreatedAtDesc(userId, pageable);
    }

    /**
     * Récupère les événements à haut risque d'un utilisateur.
     */
    public List<SecurityEventEntity> getHighRiskEvents(Long userId, int minScore) {
        return securityEventRepository.findHighRiskEvents(userId, minScore);
    }

    /**
     * Récupère les événements récents d'un utilisateur.
     */
    public List<SecurityEventEntity> getRecentEvents(Long userId, Instant since) {
        return securityEventRepository.findRecentEvents(userId, since);
    }

    /**
     * Compte les événements d'un type spécifique dans une période.
     */
    public long countEventsByType(Long userId, SecurityEventType type, Instant start, Instant end) {
        return securityEventRepository.countByUserIdAndTypeBetween(userId, type, start, end);
    }

    /**
     * Helper pour extraire le pays depuis la requête (via header ou GeoIP).
     */
    private String extractCountryFromRequest(HttpServletRequest request) {
        // En production, utiliser un service GeoIP comme MaxMind
        // Pour l'instant, essayer de lire depuis un header (si proxy/CDN le fournit)
        String country = request.getHeader("X-Country-Code");
        if (country == null || country.isEmpty()) {
            country = request.getHeader("CF-IPCountry"); // Cloudflare
        }
        return country;
    }

    /**
     * Helper pour extraire la ville depuis la requête.
     */
    private String extractCityFromRequest(HttpServletRequest request) {
        // En production, utiliser MaxMind GeoIP2
        String city = request.getHeader("X-City");
        if (city == null || city.isEmpty()) {
            city = request.getHeader("CF-IPCity"); // Cloudflare
        }
        return city;
    }

    /**
     * Sérialise les détails additionnels en JSON.
     */
    private String serializeDetails(Map<String, Object> details) {
        if (details == null || details.isEmpty()) {
            return null;
        }

        try {
            return objectMapper.writeValueAsString(details);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize event details", e);
            return "{\"error\": \"Failed to serialize\"}";
        }
    }

    /**
     * Crée un map de détails pour un login réussi.
     */
    public static Map<String, Object> createLoginSuccessDetails(String method, boolean mfaUsed) {
        Map<String, Object> details = new HashMap<>();
        details.put("method", method); // "password", "webauthn", "totp"
        details.put("mfaUsed", mfaUsed);
        details.put("timestamp", Instant.now().toString());
        return details;
    }

    /**
     * Crée un map de détails pour un login échoué.
     */
    public static Map<String, Object> createLoginFailureDetails(String reason) {
        Map<String, Object> details = new HashMap<>();
        details.put("reason", reason);
        details.put("timestamp", Instant.now().toString());
        return details;
    }

    /**
     * Crée un map de détails pour une anomalie de session.
     */
    public static Map<String, Object> createAnomalyDetails(String oldFingerprint, String newFingerprint,
            int riskScore) {
        Map<String, Object> details = new HashMap<>();
        details.put("oldFingerprint", oldFingerprint);
        details.put("newFingerprint", newFingerprint);
        details.put("riskScore", riskScore);
        details.put("timestamp", Instant.now().toString());
        return details;
    }
}
