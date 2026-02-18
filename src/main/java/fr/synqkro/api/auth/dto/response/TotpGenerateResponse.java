package fr.synqkro.api.auth.dto.response;

public record TotpGenerateResponse(
        String secret,
        String otpauthUrl) {
}
