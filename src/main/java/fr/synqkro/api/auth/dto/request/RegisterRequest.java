package fr.synqkro.api.auth.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.validation.annotation.Validated;

@Validated
public record RegisterRequest (
    @NotBlank(message="USERNAME_REQUIRED")
    @Size(min=3, max=32, message="USERNAME_INVALID_LENGTH")
    @Pattern(regexp = "^[a-zA-Z0-9_]+$", message = "USERNAME_INVALID_FORMAT")
    String username,

    @NotBlank(message = "EMAIL_REQUIRED")
    @Email(message = "EMAIL_INVALID")
    String email,

    @NotBlank(message = "PASSWORD_REQUIRED")
    @Size(min = 8, max = 128, message = "PASSWORD_INVALID_LENGTH")
    String password

) {}