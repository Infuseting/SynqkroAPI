package fr.synqkro.api.common.filter;

import fr.synqkro.api.common.config.RateLimitConfig;
import fr.synqkro.api.common.exception.RateLimitExceededException;
import fr.synqkro.api.common.service.FingerprintService;
import fr.synqkro.api.common.service.RateLimitService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
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

/**
 * Filtre global de rate limiting.
 * S'exécute en premier pour bloquer les requêtes excessives.
 */
@Component
@Order(1)
@RequiredArgsConstructor
@Slf4j
public class RateLimitFilter extends OncePerRequestFilter {

    private final RateLimitService rateLimitService;
    private final FingerprintService fingerprintService;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String path = request.getRequestURI();
        RateLimitConfig config = determineRateLimitConfig(path);

        if (config != null) {
            String key = determineKey(request, config);

            if (!rateLimitService.tryConsume(key, config)) {
                long retryAfter = rateLimitService.getSecondsToRefill(key, config);
                handleRateLimitExceeded(response, key, retryAfter);
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    /**
     * Détermine la configuration de rate limit selon la route.
     */
    private RateLimitConfig determineRateLimitConfig(String path) {
        // Public routes (par IP)
        if (path.startsWith("/auth/login"))
            return RateLimitConfig.LOGIN;
        if (path.startsWith("/auth/register"))
            return RateLimitConfig.REGISTER_HOURLY;
        if (path.startsWith("/auth/email/confirm"))
            return RateLimitConfig.EMAIL_CONFIRM;
        if (path.startsWith("/auth/password/forgot"))
            return RateLimitConfig.PASSWORD_FORGOT;
        if (path.startsWith("/auth/password/reset"))
            return RateLimitConfig.PASSWORD_RESET;

        // Authenticated routes (par user)
        if (path.startsWith("/auth/refresh"))
            return RateLimitConfig.REFRESH;
        if (path.startsWith("/auth/me"))
            return RateLimitConfig.ME;
        if (path.startsWith("/auth/sessions"))
            return RateLimitConfig.SESSIONS_LIST;

        // TOTP routes
        if (path.startsWith("/auth/totp/generate"))
            return RateLimitConfig.TOTP_GENERATE;
        if (path.startsWith("/auth/totp/validate"))
            return RateLimitConfig.TOTP_VALIDATE;
        if (path.startsWith("/auth/totp/disable"))
            return RateLimitConfig.TOTP_DISABLE;

        // Password/Email
        if (path.startsWith("/auth/password/change"))
            return RateLimitConfig.PASSWORD_CHANGE;
        if (path.startsWith("/auth/email/change"))
            return RateLimitConfig.EMAIL_CHANGE;

        // Devices
        if (path.startsWith("/auth/devices") && path.contains("/trust"))
            return RateLimitConfig.DEVICE_TRUST;
        if (path.startsWith("/auth/devices") && path.contains("/revoke"))
            return RateLimitConfig.DEVICE_REVOKE;

        // Critical
        if (path.startsWith("/auth/delete"))
            return RateLimitConfig.DELETE_ACCOUNT;
        if (path.startsWith("/auth/sessions/revoke-all"))
            return RateLimitConfig.REVOKE_ALL;
        if (path.startsWith("/auth/export"))
            return RateLimitConfig.EXPORT;

        // WebAuthn
        if (path.startsWith("/auth/webauthn/register"))
            return RateLimitConfig.WEBAUTHN_REGISTER;
        if (path.startsWith("/auth/webauthn/auth"))
            return RateLimitConfig.WEBAUTHN_AUTH;

        // Global par défaut
        return RateLimitConfig.GLOBAL;
    }

    /**
     * Détermine la clé de rate limiting (IP ou userId).
     */
    private String determineKey(HttpServletRequest request, RateLimitConfig config) {
        // Routes publiques = par IP
        if (isPublicRoute(config)) {
            return fingerprintService.extractClientIp(request);
        }

        // Routes authentifiées = par userId
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal())) {
            Long userId = extractUserId(auth);
            if (userId != null) {
                return String.valueOf(userId);
            }
        }

        // Fallback sur IP
        return fingerprintService.extractClientIp(request);
    }

    /**
     * Vérifie si la route est publique.
     */
    private boolean isPublicRoute(RateLimitConfig config) {
        return config == RateLimitConfig.GLOBAL ||
                config == RateLimitConfig.LOGIN ||
                config == RateLimitConfig.REGISTER_HOURLY ||
                config == RateLimitConfig.REGISTER_DAILY ||
                config == RateLimitConfig.EMAIL_CONFIRM ||
                config == RateLimitConfig.PASSWORD_FORGOT ||
                config == RateLimitConfig.PASSWORD_RESET;
    }

    /**
     * Gère le dépassement de rate limit.
     */
    private void handleRateLimitExceeded(HttpServletResponse response, String key, long retryAfter) throws IOException {
        response.setStatus(429); // Too Many Requests
        response.setHeader("Retry-After", String.valueOf(retryAfter));
        response.setHeader("X-RateLimit-Retry-After", String.valueOf(retryAfter));
        response.setContentType("application/json");

        String json = String.format(
                "{\"error\":\"RATE_LIMIT_EXCEEDED\",\"message\":\"Too many requests. Retry after %d seconds.\",\"retryAfter\":%d}",
                retryAfter, retryAfter);

        response.getWriter().write(json);

        log.warn("Rate limit exceeded for key: {} (retry after: {}s)", key, retryAfter);
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
}
