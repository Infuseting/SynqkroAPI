package fr.synqkro.api.auth.dto.response;

public record TokenResponse(
        String accessToken,
        String tokenType,
        long expiresIn
) {}
