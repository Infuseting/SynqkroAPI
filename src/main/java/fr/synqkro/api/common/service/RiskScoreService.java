package fr.synqkro.api.common.service;

import fr.synqkro.api.common.entity.SecurityEventEntity;
import fr.synqkro.api.common.enums.SecurityEventType;
import fr.synqkro.api.common.repository.SecurityEventRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

/**
 * Service de calcul du score de risque pour l'authentification.
 * Inspiré d'AWS GuardDuty, Cloudflare Bot Score, et Google Safe Browsing.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class RiskScoreService {

    private final SecurityEventRepository securityEventRepository;
    private final FingerprintService fingerprintService;
    private final TrustedDeviceService trustedDeviceService;
    private final GeoLocationService geoLocationService;

    // Seuils de risque
    private static final int RISK_LOW = 20;
    private static final int RISK_MODERATE = 50;
    private static final int RISK_HIGH = 75;
    private static final int RISK_CRITICAL = 100;

    // Points de risque par facteur
    private static final int POINTS_VPN_DETECTED = 40;
    private static final int POINTS_BLACKLISTED_COUNTRY = 40;
    private static final int POINTS_IMPOSSIBLE_TRAVEL = 60;
    private static final int POINTS_NEW_LOCATION = 20;
    private static final int POINTS_UNTRUSTED_DEVICE = 30;
    private static final int POINTS_NEW_FINGERPRINT = 25;
    private static final int POINTS_SUSPICIOUS_UA = 50;
    private static final int POINTS_MULTIPLE_LOGIN_FAILURES = 35;
    private static final int POINTS_VELOCITY_ANOMALY = 45;
    private static final int POINTS_BOT_PATTERN = 70;
    private static final int POINTS_DATACENTER_IP = 30;
    private static final int POINTS_BLACKLISTED_IP = 80;
    private static final int POINTS_TOR_NODE = 60;

    /**
     * Contexte de login pour le calcul de risque.
     */
    @lombok.Data
    @lombok.Builder
    public static class LoginContext {
        private Long userId;
        private String ip;
        private String countryCode;
        private String city;
        private Double latitude;
        private Double longitude;
        private String userAgent;
        private String fingerprint;
        private HttpServletRequest request;
    }

    /**
     * Calcule le score de risque total pour un contexte de login.
     * 
     * @return score de 0 à 100
     */
    public int calculateRiskScore(LoginContext ctx) {
        int score = 0;

        // 1. Facteurs géographiques
        score += calculateGeoRiskScore(ctx);

        // 2. Facteurs d'appareil
        score += calculateDeviceRiskScore(ctx);

        // 3. Facteurs comportementaux
        score += calculateBehavioralRiskScore(ctx);

        // 4. Facteurs réseau
        score += calculateNetworkRiskScore(ctx);

        int finalScore = Math.min(RISK_CRITICAL, score);
        log.debug("Calculated risk score for user {}: {}", ctx.getUserId(), finalScore);
        return finalScore;
    }

    /**
     * Calcule le risque géographique.
     */
    private int calculateGeoRiskScore(LoginContext ctx) {
        int score = 0;

        if (ctx.getUserId() != null && ctx.getCountryCode() != null) {
            // Vérifier impossible travel
            List<SecurityEventEntity> recentLogins = securityEventRepository
                    .findRecentLoginsForTravelDetection(ctx.getUserId(), Instant.now().minus(Duration.ofHours(1)));

            if (!recentLogins.isEmpty()) {
                SecurityEventEntity lastLogin = recentLogins.get(0);

                // Si pays différent et < 1h = impossible travel
                if (lastLogin.getCountryCode() != null &&
                        !lastLogin.getCountryCode().equals(ctx.getCountryCode())) {
                    score += POINTS_IMPOSSIBLE_TRAVEL;
                    log.warn("Impossible travel detected for user {}: {} -> {} in <1h",
                            ctx.getUserId(), lastLogin.getCountryCode(), ctx.getCountryCode());
                }

                // Nouvelle géolocalisation (différente mais pas impossible travel)
                if (lastLogin.getCity() != null && ctx.getCity() != null &&
                        !lastLogin.getCity().equals(ctx.getCity())) {
                    score += POINTS_NEW_LOCATION;
                }
            }
        }

        return score;
    }

    /**
     * Calcule le risque lié à l'appareil.
     */
    private int calculateDeviceRiskScore(LoginContext ctx) {
        int score = 0;

        if (ctx.getUserId() != null && ctx.getFingerprint() != null) {
            // Device non trusted
            if (!trustedDeviceService.isTrusted(ctx.getUserId(), ctx.getFingerprint())) {
                score += POINTS_UNTRUSTED_DEVICE;
            }

            // Nouveau fingerprint jamais vu pour cet utilisateur
            if (!securityEventRepository.existsByUserIdAndDetailsContainingFingerprint(ctx.getUserId(),
                    ctx.getFingerprint())) {
                score += POINTS_NEW_FINGERPRINT;
            }
        }



        return score;
    }

    /**
     * Calcule le risque comportemental.
     */
    private int calculateBehavioralRiskScore(LoginContext ctx) {
        int score = 0;

        if (ctx.getUserId() != null) {
            // Tentatives de login récentes
            long loginAttempts = securityEventRepository.countLoginAttempts(
                    ctx.getUserId(),
                    Instant.now().minus(Duration.ofMinutes(15)));

            if (loginAttempts > 5) {
                score += POINTS_MULTIPLE_LOGIN_FAILURES;
            }

            if (loginAttempts > 10) {
                score += POINTS_VELOCITY_ANOMALY;
            }
        }

        // Vérifier échecs de login récents par IP
        if (ctx.getIp() != null) {
            List<SecurityEventEntity> ipFailures = securityEventRepository
                    .findRecentLoginFailuresByIp(ctx.getIp(), Instant.now().minus(Duration.ofMinutes(15)));

            if (ipFailures.size() > 5) {
                score += POINTS_BOT_PATTERN;
            }
        }

        return score;
    }

    /**
     * Calcule le risque réseau.
     */
    private int calculateNetworkRiskScore(LoginContext ctx) {
        int score = 0;

        if (ctx.getIp() != null) {
            // Vérifier si IP de datacenter/VPN (via ASN)
            if (geoLocationService.isDatacenterIp(ctx.getIp())) {
                score += POINTS_DATACENTER_IP;
            }


        }

        return score;
    }

    /**
     * Détermine si une MFA additionnelle est requise.
     */
    public boolean requiresAdditionalMfa(int riskScore) {
        return riskScore >= RISK_HIGH;
    }

    /**
     * Détermine si un CAPTCHA est requis.
     */
    public boolean requiresCaptcha(int riskScore) {
        return riskScore >= RISK_HIGH;
    }

    /**
     * Détermine si le login doit être bloqué.
     */
    public boolean shouldBlockLogin(int riskScore) {
        return riskScore >= RISK_CRITICAL;
    }


}
