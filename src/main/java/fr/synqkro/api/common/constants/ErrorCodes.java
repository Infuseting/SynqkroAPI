package fr.synqkro.api.common.constants;

/**
 * Codes d'erreur constants pour l'API.
 * Utilisés dans ApiException et ErrorResponse pour une gestion cohérente des
 * erreurs.
 */
public final class ErrorCodes {

    private ErrorCodes() {
        // Classe utilitaire, ne peut pas être instanciée
    }

    // ========== Authentification ==========
    public static final String INVALID_CREDENTIALS = "INVALID_CREDENTIALS";
    public static final String USER_NOT_FOUND = "USER_NOT_FOUND";
    public static final String EMAIL_ALREADY_EXISTS = "EMAIL_ALREADY_EXISTS";
    public static final String USERNAME_ALREADY_EXISTS = "USERNAME_ALREADY_EXISTS";
    public static final String ACCOUNT_DISABLED = "ACCOUNT_DISABLED";
    public static final String ACCOUNT_LOCKED = "ACCOUNT_LOCKED";
    public static final String EMAIL_NOT_VERIFIED = "EMAIL_NOT_VERIFIED";

    // ========== Tokens ==========
    public static final String INVALID_TOKEN = "INVALID_TOKEN";
    public static final String EXPIRED_TOKEN = "EXPIRED_TOKEN";
    public static final String TOKEN_NOT_FOUND = "TOKEN_NOT_FOUND";
    public static final String REFRESH_TOKEN_EXPIRED = "REFRESH_TOKEN_EXPIRED";
    public static final String REFRESH_TOKEN_INVALID = "REFRESH_TOKEN_INVALID";

    // ========== TOTP/2FA ==========
    public static final String TOTP_REQUIRED = "TOTP_REQUIRED";
    public static final String TOTP_INVALID = "TOTP_INVALID";
    public static final String TOTP_ALREADY_ENABLED = "TOTP_ALREADY_ENABLED";
    public static final String TOTPnot_ENABLED = "TOTP_NOT_ENABLED";
    public static final String RECOVERY_CODE_INVALID = "RECOVERY_CODE_INVALID";

    // ========== Sessions ==========
    public static final String SESSION_NOT_FOUND = "SESSION_NOT_FOUND";
    public static final String SESSION_EXPIRED = "SESSION_EXPIRED";
    public static final String CONCURRENT_SESSION_LIMIT = "CONCURRENT_SESSION_LIMIT";

    // ========== Devices ==========
    public static final String DEVICE_NOT_FOUND = "DEVICE_NOT_FOUND";
    public static final String DEVICE_ALREADY_TRUSTED = "DEVICE_ALREADY_TRUSTED";

    // ========== Validation ==========
    public static final String VALIDATION_ERROR = "VALIDATION_ERROR";
    public static final String INVALID_INPUT = "INVALID_INPUT";
    public static final String MISSING_REQUIRED_FIELD = "MISSING_REQUIRED_FIELD";

    // ========== Mots de passe ==========
    public static final String INVALID_PASSWORD = "INVALID_PASSWORD";
    public static final String PASSWORD_TOO_WEAK = "PASSWORD_TOO_WEAK";
    public static final String PASSWORD_RESET_REQUIRED = "PASSWORD_RESET_REQUIRED";

    // ========== Rate Limiting ==========
    public static final String RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED";
    public static final String TOO_MANY_REQUESTS = "TOO_MANY_REQUESTS";

    // ========== Génériques ==========
    public static final String INTERNAL_SERVER_ERROR = "INTERNAL_SERVER_ERROR";
    public static final String SERVICE_UNAVAILABLE = "SERVICE_UNAVAILABLE";
    public static final String UNAUTHORIZED = "UNAUTHORIZED";
    public static final String FORBIDDEN = "FORBIDDEN";
    public static final String NOT_FOUND = "NOT_FOUND";
    public static final String BAD_REQUEST = "BAD_REQUEST";
    public static final String CONFLICT = "CONFLICT";

    // ========== Email ==========
    public static final String EMAIL_SEND_FAILED = "EMAIL_SEND_FAILED";
    public static final String EMAIL_VERIFICATION_FAILED = "EMAIL_VERIFICATION_FAILED";
}
