package fr.synqkro.api.auth.dto.request;

import jakarta.validation.constraints.NotNull;



public record RevokeSessionRequest(
                @NotNull(message = "SESSION_ID_REQUIRED")
                Long sessionId
) {
}
