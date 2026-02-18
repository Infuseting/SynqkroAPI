package fr.synqkro.api.common.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "sessions", indexes = {
        @Index(name = "idx_sessions_user_id", columnList = "user_id"),
        @Index(name = "idx_sessions_refresh_token_id", columnList = "refresh_token_id", unique = true),
        @Index(name = "idx_sessions_trusted_device_id", columnList = "trusted_device_id"),
        @Index(name = "idx_sessions_last_seen_at", columnList = "last_seen_at")
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SessionEntity {

    @Id
    @Column(nullable = false, updatable = false)
    private Long id; // Snowflake ID

    @Column(name = "user_id", nullable = false, updatable = false)
    private Long userId;

    @Column(name = "refresh_token_id", nullable = false, updatable = false)
    private Long refreshTokenId;

    @Column(name = "trusted_device_id")
    private Long trustedDeviceId; // nullable si device non trusted

    @Column(name = "fingerprint", nullable = false, length = 64)
    private String fingerprint; // hash(IP subnet + UA + lang)

    @Column(name = "advanced_fingerprint", length = 64)
    private String advancedFingerprint; // hash(canvas + webgl + audio + fonts) from client

    @Column(name = "ip", length = 45)
    private String ip;

    @Column(name = "user_agent", length = 512)
    private String userAgent;

    @Column(name = "country_code", length = 2)
    private String countryCode;

    @Column(name = "city", length = 100)
    private String city; // via GeoIP

    @Column(name = "latitude")
    private Double latitude;

    @Column(name = "longitude")
    private Double longitude;

    @Column(name = "risk_score", nullable = false)
    @Builder.Default
    private Integer riskScore = 0; // 0-100, incrémenté à chaque anomalie

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "last_seen_at", nullable = false)
    private Instant lastSeenAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
        if (lastSeenAt == null) {
            lastSeenAt = Instant.now();
        }
    }

    @PreUpdate
    protected void onUpdate() {
        lastSeenAt = Instant.now();
    }

    public void incrementRiskScore(int points) {
        this.riskScore = Math.min(100, this.riskScore + points);
    }

    public boolean isHighRisk() {
        return riskScore >= 50;
    }

    public boolean isCriticalRisk() {
        return riskScore >= 75;
    }
}
