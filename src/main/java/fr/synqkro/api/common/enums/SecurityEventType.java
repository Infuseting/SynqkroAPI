package fr.synqkro.api.common.enums;

public enum SecurityEventType {
    // Login events
    LOGIN_SUCCESS,
    LOGIN_FAILED,
    LOGIN_BLOCKED,
    LOGIN_MFA_REQUIRED,

    // Logout events
    LOGOUT,

    // MFA events
    MFA_ENABLED,
    MFA_DISABLED,
    MFA_TOTP_VALIDATED,
    MFA_TOTP_FAILED,
    MFA_RECOVERY_CODE_USED,
    MFA_WEBAUTHN_REGISTERED,
    MFA_WEBAUTHN_REMOVED,

    // Password events
    PASSWORD_CHANGED,
    PASSWORD_RESET_REQUESTED,
    PASSWORD_RESET_COMPLETED,

    // Email events
    EMAIL_CHANGED,
    EMAIL_VERIFIED,

    // Device/Session events
    DEVICE_TRUSTED,
    DEVICE_REVOKED,
    SESSION_REVOKED,
    SESSION_REVOKED_ALL,
    SESSION_ANOMALY,

    // Security alerts
    SUSPICIOUS_ACTIVITY,
    IMPOSSIBLE_TRAVEL_DETECTED,
    FINGERPRINT_ANOMALY,
    HIGH_RISK_LOGIN,

    // Account events
    ACCOUNT_DELETED,
    ACCOUNT_EXPORT_REQUESTED
}
