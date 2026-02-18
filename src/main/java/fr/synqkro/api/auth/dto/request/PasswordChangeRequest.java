package fr.synqkro.api.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;


public record PasswordChangeRequest(
                @NotBlank(message = "OLD_PASSWORD_REQUIRED")
                String oldPassword,

                @NotBlank(message = "NEW_PASSWORD_REQUIRED")
                @Size(min = 8, max = 128, message = "NEW_PASSWORD_INVALID_LENGTH")
                String newPassword) {
}
