package fr.synqkro.api.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.validation.annotation.Validated;

@Validated
public record LoginRequest(

        @NotBlank(message = "EMAIL_OR_USERNAME_REQUIRED")
        @Size(max = 254, message = "EMAIL_OR_USERNAME_TOO_LONG")
        String usernameOrEmail,

        @NotBlank(message = "PASSWORD_REQUIRED")
        @Size(min = 8, max = 128, message = "PASSWORD_INVALID_LENGTH")
        String password,

        @Size(max = 6, message = "TOTP_INVALID_LENGTH")
        @Pattern(regexp = "^[0-9]{6}$", message = "TOTP_INVALID_FORMAT")
        String totpCode

) {

        public LoginRequest {
                usernameOrEmail = usernameOrEmail != null ? usernameOrEmail.strip() : null;
                totpCode   = totpCode   != null ? totpCode.strip()   : null;
        }

        public boolean hasTotpCode() {
                return totpCode != null && !totpCode.isBlank();
        }
}