package fr.synqkro.api.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record TotpValidateRequest(
                @NotBlank(message = "TOTP_CODE_REQUIRED")
                @Size(min = 6, max = 6, message = "TOTP_CODE_INVALID_LENGTH")
                @Pattern(regexp = "^[0-9]{6}$", message = "TOTP_CODE_INVALID_FORMAT")
                String code
) {
}
