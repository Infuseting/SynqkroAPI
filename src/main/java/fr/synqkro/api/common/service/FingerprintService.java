package fr.synqkro.api.common.service;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Service pour le calcul et la validation des fingerprints (empreintes
 * d'appareil).
 * Inspiré des systèmes de Google, Discord, et AWS pour la détection de vol de
 * token.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class FingerprintService {

    private static final int RISK_THRESHOLD_MINOR = 5;
    private static final int RISK_THRESHOLD_MODERATE = 30;
    private static final int RISK_THRESHOLD_MAJOR = 70;
    private static final int RISK_THRESHOLD_CRITICAL = 100;

    /**
     * Calcule le fingerprint basique côté serveur.
     * Basé sur : IP subnet + User-Agent + Accept-Language
     */
    public String calculateFingerprint(HttpServletRequest request) {
        String ip = extractClientIp(request);
        String ipSubnet = extractIpSubnet(ip);
        String userAgent = request.getHeader("User-Agent");
        String acceptLanguage = request.getHeader("Accept-Language");

        String raw = ipSubnet + "|" + (userAgent != null ? userAgent : "unknown")
                + "|" + (acceptLanguage != null ? acceptLanguage : "unknown");

        return sha256Hash(raw);
    }

    /**
     * Calcule le fingerprint avancé à partir des données client.
     * Données client : canvas, webgl, audio, fonts, timezone, screen résolution,
     * etc.
     */
    public String calculateAdvancedFingerprint(FingerprintData data) {
        if (data == null) {
            return null;
        }

        StringBuilder raw = new StringBuilder();
        raw.append(data.getCanvasFingerprint() != null ? data.getCanvasFingerprint() : "");
        raw.append("|");
        raw.append(data.getWebglFingerprint() != null ? data.getWebglFingerprint() : "");
        raw.append("|");
        raw.append(data.getAudioFingerprint() != null ? data.getAudioFingerprint() : "");
        raw.append("|");
        raw.append(data.getFonts() != null ? String.join(",", data.getFonts()) : "");
        raw.append("|");
        raw.append(data.getTimezone() != null ? data.getTimezone() : "");
        raw.append("|");
        raw.append(data.getScreenResolution() != null ? data.getScreenResolution() : "");

        return sha256Hash(raw.toString());
    }

    /**
     * Détecte si le changement de fingerprint est significatif.
     */
    public boolean isSignificantChange(String oldFingerprint, String newFingerprint) {
        if (oldFingerprint == null || newFingerprint == null) {
            return true;
        }

        if (oldFingerprint.equals(newFingerprint)) {
            return false;
        }

        // Tout changement de fingerprint est considéré significatif dans cette
        // implémentation simple
        // Une implémentation plus avancée pourrait comparer les composants individuels
        return true;
    }

    /**
     * Calcule le score de risque basé sur le changement de fingerprint.
     * 
     * @return score de 0 à 100
     */
    public int calculateRiskScore(String oldFingerprint, String newFingerprint) {
        if (oldFingerprint == null || newFingerprint == null) {
            return RISK_THRESHOLD_MODERATE; // 30 points si pas de fingerprint précédent
        }

        if (oldFingerprint.equals(newFingerprint)) {
            return 0; // Aucun changement = pas de risque
        }

        // Dans une vraie impl, on comparerait composant par composant
        // Pour l'instant, tout changement = risque modéré minimum
        return RISK_THRESHOLD_MODERATE; // 30 points de base pour tout changement
    }

    /**
     * Calcule le score de risque avec contexte additionnel.
     */
    public int calculateRiskScoreWithContext(
            String oldFingerprint,
            String newFingerprint,
            String oldIp,
            String newIp,
            String oldCountry,
            String newCountry) {
        int score = calculateRiskScore(oldFingerprint, newFingerprint);

        // Changement de pays = +40 points
        if (oldCountry != null && newCountry != null && !oldCountry.equals(newCountry)) {
            score += 40;
            log.warn("Country change detected: {} -> {}", oldCountry, newCountry);
        }

        // Changement d'IP majeur (subnet différent) = +25 points
        if (oldIp != null && newIp != null) {
            String oldSubnet = extractIpSubnet(oldIp);
            String newSubnet = extractIpSubnet(newIp);
            if (!oldSubnet.equals(newSubnet)) {
                score += 25;
                log.warn("IP subnet change detected: {} -> {}", oldSubnet, newSubnet);
            }
        }

        return Math.min(100, score); // Cap à 100
    }

    /**
     * Extrait l'IP client en tenant compte des proxies/load balancers.
     */
    public String extractClientIp(HttpServletRequest request) {
        String ip = request.getHeader("X-Forwarded-For");
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("X-Real-IP");
        }
        if (ip == null || ip.isEmpty() || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }

        // Si multiple IPs (proxy chain), prendre la première
        if (ip != null && ip.contains(",")) {
            ip = ip.split(",")[0].trim();
        }

        return ip;
    }

    /**
     * Extrait le subnet IP (/24 pour IPv4, /48 pour IPv6).
     */
    public String extractIpSubnet(String ip) {
        if (ip == null) {
            return "unknown";
        }

        // IPv4
        if (ip.contains(".")) {
            String[] parts = ip.split("\\.");
            if (parts.length >= 3) {
                return parts[0] + "." + parts[1] + "." + parts[2] + ".0";
            }
        }

        // IPv6 - prendre les 3 premiers segments
        if (ip.contains(":")) {
            String[] parts = ip.split(":");
            if (parts.length >= 3) {
                return parts[0] + ":" + parts[1] + ":" + parts[2] + "::";
            }
        }

        return ip;
    }

    /**
     * Hash SHA-256 d'une string.
     */
    private String sha256Hash(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            log.error("SHA-256 algorithm not available", e);
            throw new RuntimeException("Failed to hash fingerprint", e);
        }
    }

    /**
     * DTO pour les données de fingerprint avancé envoyées par le client.
     */
    @lombok.Data
    @lombok.Builder
    @lombok.NoArgsConstructor
    @lombok.AllArgsConstructor
    public static class FingerprintData {
        private String canvasFingerprint;
        private String webglFingerprint;
        private String audioFingerprint;
        private java.util.List<String> fonts;
        private String timezone;
        private String screenResolution;
    }
}
