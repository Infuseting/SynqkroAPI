package fr.synqkro.api.auth.dto.request;

public record RevokeAllSessionsRequest(
        boolean keepCurrent
) {
}
