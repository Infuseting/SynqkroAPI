package fr.synqkro.api.auth.dto.internal;


public record TokenValidation(
        long   userId,
        long   tokenId,
        String hashedToken
) {}