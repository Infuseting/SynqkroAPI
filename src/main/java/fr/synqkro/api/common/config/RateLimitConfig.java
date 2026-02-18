package fr.synqkro.api.common.config;

import java.time.Duration;

/**
 * Configuration des limites de rate limiting par route.
 * Organisée en catégories : Public → Standard → Sensible → Critique.
 */
public enum RateLimitConfig {

    // ============================================
    // PUBLIC ROUTES (par IP)
    // ============================================

    /** Limite globale pour toutes les requêtes */
    GLOBAL(100, Duration.ofSeconds(1)),

    /** Login rate limit */
    LOGIN(10, Duration.ofMinutes(15)),

    /** Registration rate limit (hourly) */
    REGISTER_HOURLY(3, Duration.ofHours(1)),

    /** Registration rate limit (daily) */
    REGISTER_DAILY(10, Duration.ofDays(1)),

    /** Email confirmation */
    EMAIL_CONFIRM(5, Duration.ofHours(1)),

    /** Password forgot request */
    PASSWORD_FORGOT(3, Duration.ofHours(1)),

    /** Password reset */
    PASSWORD_RESET(5, Duration.ofHours(1)),

    // ============================================
    // AUTHENTICATED - STANDARD (par user)
    // ============================================

    /** Token refresh */
    REFRESH(60, Duration.ofHours(1)), // 1 par minute

    /** Get current user profile */
    ME(120, Duration.ofHours(1)), // 2 par minute

    /** List sessions */
    SESSIONS_LIST(30, Duration.ofHours(1)),

    // ============================================
    // AUTHENTICATED - SENSITIVE (par user)
    // ============================================

    /** TOTP generation */
    TOTP_GENERATE(3, Duration.ofHours(1)),

    /** TOTP validation */
    TOTP_VALIDATE(5, Duration.ofMinutes(5)),

    /** TOTP disable */
    TOTP_DISABLE(3, Duration.ofHours(1)),

    /** Password change */
    PASSWORD_CHANGE(5, Duration.ofHours(1)),

    /** Email change */
    EMAIL_CHANGE(3, Duration.ofHours(1)),

    /** Trust a device */
    DEVICE_TRUST(10, Duration.ofDays(1)),

    /** Revoke a device */
    DEVICE_REVOKE(20, Duration.ofHours(1)),

    // ============================================
    // AUTHENTICATED - CRITICAL (par user)
    // ============================================

    /** Delete account */
    DELETE_ACCOUNT(1, Duration.ofDays(7)),

    /** Revoke all sessions */
    REVOKE_ALL(5, Duration.ofHours(1)),

    /** RGPD export request */
    EXPORT(1, Duration.ofDays(30)),

    // ============================================
    // WEBAUTHN (par user)
    // ============================================

    /** Register WebAuthn credential */
    WEBAUTHN_REGISTER(10, Duration.ofDays(1)),

    /** WebAuthn authentication - pas de limite (c'est un facteur d'auth) */
    WEBAUTHN_AUTH(1000, Duration.ofMinutes(1));

    private final int capacity;
    private final Duration window;

    RateLimitConfig(int capacity, Duration window) {
        this.capacity = capacity;
        this.window = window;
    }

    public int getCapacity() {
        return capacity;
    }

    public Duration getWindow() {
        return window;
    }

    public long getWindowSeconds() {
        return window.getSeconds();
    }
}
