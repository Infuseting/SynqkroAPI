package fr.synqkro.api.auth.dto.request;

import jakarta.validation.constraints.NotBlank;



public record TotpDisableRequest(
                @NotBlank(message = "TOTP_CODE_REQUIRED")
                String code
) {
}
