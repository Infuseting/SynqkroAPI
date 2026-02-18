package fr.synqkro.api.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/**
 * Requête de réinitialisation de mot de passe.
 * Deux flows possibles :
 * <ul>
 * <li>Via token email : {@code token} + {@code newPassword}</li>
 * <li>Via TOTP : {@code email} + {@code totpCode} + {@code newPassword}</li>
 * </ul>
 */
public record PasswordResetRequest(
        /** Token reçu par email (flow sans TOTP). */
        String token,

        /** Email de l'utilisateur (requis pour le flow TOTP). */
        String email,

        /** Code TOTP ou recovery code (flow TOTP). */
        String totpCode,

        @NotBlank(message = "NEW_PASSWORD_REQUIRED") @Size(min = 8, max = 128, message = "NEW_PASSWORD_INVALID_LENGTH") String newPassword) {
}
