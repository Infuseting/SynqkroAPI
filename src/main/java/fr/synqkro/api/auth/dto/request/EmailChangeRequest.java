package fr.synqkro.api.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record EmailChangeRequest(
                @NotBlank(message = "EMAIL_REQUIRED")
                @Email(message = "EMAIL_INVALID")
                String newEmail
) {
}
