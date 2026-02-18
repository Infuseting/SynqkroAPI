package fr.synqkro.api.auth.dto.response;

import fr.synqkro.api.common.entity.SessionEntity;

import java.time.Instant;


public record SessionDto(
        String sessionId,
        String ip,
        String userAgent,
        String city,
        String countryCode,
        String deviceName,
        boolean current,
        int riskScore,
        Instant createdAt,
        Instant lastSeenAt) {

    public static SessionDto fromEntity(SessionEntity entity, boolean isCurrent, String deviceName) {
        return new SessionDto(
                String.valueOf(entity.getId()),
                entity.getIp(),
                entity.getUserAgent(),
                entity.getCity(),
                entity.getCountryCode(),
                deviceName,
                isCurrent,
                entity.getRiskScore(),
                entity.getCreatedAt(),
                entity.getLastSeenAt());
    }

    public static SessionDto fromEntity(SessionEntity entity, boolean isCurrent) {
        return fromEntity(entity, isCurrent, null);
    }
}
