package fr.synqkro.api.auth.dto.response;

public record UserProfileResponse(
        String id,
        String username,
        String email,
        String avatarKey,
        boolean emailVerified,
        String createdAt
) {}

