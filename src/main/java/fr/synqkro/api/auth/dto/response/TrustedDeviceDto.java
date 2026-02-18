package fr.synqkro.api.auth.dto.response;

import fr.synqkro.api.common.entity.TrustedDeviceEntity;

import java.time.Instant;


public record TrustedDeviceDto(
        String id,
        String name,
        String fingerprint,
        String lastIp,
        String lastCountryCode,
        boolean trusted,
        Instant lastUsedAt,
        Instant expiresAt) {

    public static TrustedDeviceDto fromEntity(TrustedDeviceEntity entity) {
        return new TrustedDeviceDto(
                String.valueOf(entity.getId()),
                entity.getName(),
                entity.getFingerprint(),
                entity.getLastIp(),
                entity.getLastCountryCode(),
                entity.isTrusted(),
                entity.getLastUsedAt(),
                entity.getExpiresAt());
    }
}
