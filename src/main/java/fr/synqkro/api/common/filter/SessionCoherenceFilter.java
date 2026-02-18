package fr.synqkro.api.common.filter;

import fr.synqkro.api.common.entity.SessionEntity;
import fr.synqkro.api.common.enums.SecurityEventType;
import fr.synqkro.api.common.exception.SessionAnomalyException;
import fr.synqkro.api.common.repository.RefreshTokenRepository;
import fr.synqkro.api.common.repository.SessionRepository;
import fr.synqkro.api.common.repository.UserRepository;
import fr.synqkro.api.common.service.EmailService;
import fr.synqkro.api.common.service.FingerprintService;
import fr.synqkro.api.common.service.SecurityEventService;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;

/**
 * Filtre pour détecter les vols de token via changement de fingerprint.
 * S'exécute après JwtAuthenticationFilter pour vérifier la cohérence de la
 * session.
 */
@Component
@Order(3)
@RequiredArgsConstructor
@Slf4j
public class SessionCoherenceFilter extends OncePerRequestFilter {

    private final FingerprintService fingerprintService;
    private final SessionRepository sessionRepository;
    private final RefreshTokenRepository refreshTokenRepository;
    private final SecurityEventService securityEventService;
    private final EmailService emailService;

    private final UserRepository userRepository;

    @org.springframework.beans.factory.annotation.Value("${app.url:https://synqkro.fr}")
    private String appUrl;

    private static final int RISK_THRESHOLD_REVOKE = 70;
    private static final List<String> EXCLUDED_PATHS = Arrays.asList(
            "/auth/login",
            "/auth/register",
            "/auth/refresh",
            "/auth/password/forgot",
            "/auth/password/reset",
            "/auth/email/confirm");

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        // Skip pour routes publiques
        String path = request.getRequestURI();
        if (EXCLUDED_PATHS.stream().anyMatch(path::startsWith)) {
            filterChain.doFilter(request, response);
            return;
        }

        // Vérifier si utilisateur authentifié
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !auth.isAuthenticated() || "anonymousUser".equals(auth.getPrincipal())) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            Long userId = extractUserId(auth);
            if (userId != null) {
                verifySessionCoherence(userId, request);
            }

            filterChain.doFilter(request, response);

        } catch (SessionAnomalyException e) {
            log.error("Session anomaly detected", e);
            handleSessionAnomaly(e, request, response);
        }
    }

    /**
     * Vérifie la cohérence de la session.
     */
    private void verifySessionCoherence(Long userId, HttpServletRequest request) {
        // Calculer fingerprint actuel
        String currentFingerprint = fingerprintService.calculateFingerprint(request);
        String currentIp = fingerprintService.extractClientIp(request);
        String currentCountry = extractCountry(request);

        // Récupérer la session la plus récente
        List<SessionEntity> sessions = sessionRepository.findAllActiveByUserId(userId);
        if (sessions.isEmpty()) {
            log.warn("No active session found for user {}", userId);
            return;
        }

        SessionEntity mostRecent = sessions.get(0);

        // Calculer score de risque
        int riskScore = fingerprintService.calculateRiskScoreWithContext(
                mostRecent.getFingerprint(),
                currentFingerprint,
                mostRecent.getIp(),
                currentIp,
                mostRecent.getCountryCode(),
                currentCountry);

        // Si changement radical = révocation immédiate
        if (riskScore >= RISK_THRESHOLD_REVOKE) {
            log.error("Critical session anomaly detected for user {}: risk score {}", userId, riskScore);

            String userAgent = request.getHeader("User-Agent");

            // Logger événement de sécurité
            securityEventService.logEvent(
                    userId,
                    SecurityEventType.SESSION_ANOMALY,
                    currentIp,
                    userAgent,
                    currentCountry,
                    null,
                    riskScore,
                    SecurityEventService.createAnomalyDetails(
                            mostRecent.getFingerprint(),
                            currentFingerprint,
                            riskScore));

            // Envoyer alerte email
            fr.synqkro.api.common.entity.UserEntity user = userRepository.findById(userId).orElse(null);
            if (user != null && user.getEmail() != null) {
                emailService.sendSessionAnomaly(
                        user.getEmail(),
                        user.getUsername(),
                        currentIp,
                        currentCountry,
                        userAgent != null ? userAgent : "Unknown",
                        riskScore,
                        appUrl + "/account/sessions"
                );
            }

            throw new SessionAnomalyException(userId, mostRecent.getFingerprint(), currentFingerprint, riskScore);
        }

        // Si risque modéré = incrémenter score
        if (riskScore > 0) {
            mostRecent.incrementRiskScore(riskScore);
            sessionRepository.save(mostRecent);
            log.warn("Session risk increased for user {}: +{} points (total: {})",
                    userId, riskScore, mostRecent.getRiskScore());
        }

        // Mettre à jour lastSeenAt
        mostRecent.setLastSeenAt(java.time.Instant.now());
        sessionRepository.save(mostRecent);
    }

    /**
     * Gère une anomalie de session.
     */
    private void handleSessionAnomaly(
            SessionAnomalyException e,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {
        // Révoquer tous les tokens de l'utilisateur
        refreshTokenRepository.revokeAllByUserId(e.getUserId(), Instant.now());
        sessionRepository.deleteByUserId(e.getUserId());

        // Retourner erreur 401
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.getWriter().write(
                "{\"error\":\"SESSION_ANOMALY\",\"message\":\"Session anomaly detected. All tokens have been revoked.\"}");
    }

    /**
     * Extrait le userId du context Spring Security.
     */
    private Long extractUserId(Authentication auth) {
        Object principal = auth.getPrincipal();
        if (principal instanceof org.springframework.security.core.userdetails.User) {
            try {
                return Long.parseLong(((org.springframework.security.core.userdetails.User) principal).getUsername());
            } catch (NumberFormatException e) {
                log.error("Failed to parse userId from principal", e);
            }
        }
        return null;
    }

    /**
     * Extrait le pays depuis headers.
     */
    private String extractCountry(HttpServletRequest request) {
        String country = request.getHeader("X-Country-Code");
        if (country == null) {
            country = request.getHeader("CF-IPCountry");
        }
        return country;
    }
}
