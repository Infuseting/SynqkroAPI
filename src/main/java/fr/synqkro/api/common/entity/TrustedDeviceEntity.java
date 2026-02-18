package fr.synqkro.api.common.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "trusted_devices", indexes = {
        @Index(name = "idx_trusted_devices_user_id", columnList = "user_id"),
        @Index(name = "idx_trusted_devices_fingerprint", columnList = "fingerprint"),
        @Index(name = "idx_trusted_devices_user_fingerprint", columnList = "user_id,fingerprint", unique = true),
        @Index(name = "idx_trusted_devices_expires_at", columnList = "expires_at")
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class TrustedDeviceEntity {

    @Id
    @Column(nullable = false, updatable = false)
    private Long id; // Snowflake ID

    @Column(name = "user_id", nullable = false, updatable = false)
    private Long userId;

    @Column(name = "name", length = 100)
    private String name; // "iPhone de John", "PC bureau"

    @Column(name = "fingerprint", nullable = false, length = 64)
    private String fingerprint; // device fingerprint avancé

    @Column(name = "last_ip", length = 45)
    private String lastIp;

    @Column(name = "last_user_agent", length = 512)
    private String lastUserAgent;

    @Column(name = "last_country_code", length = 2)
    private String lastCountryCode;

    @Column(name = "trusted", nullable = false)
    @Builder.Default
    private boolean trusted = false; // true si confirmé par l'utilisateur

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt; // 30 jours après création (renouvelé à chaque usage)

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
        if (expiresAt == null) {
            expiresAt = Instant.now().plusSeconds(30L * 24 * 60 * 60); // 30 jours
        }
        if (lastUsedAt == null) {
            lastUsedAt = createdAt;
        }
    }

    public void renewExpiration() {
        this.expiresAt = Instant.now().plusSeconds(30L * 24 * 60 * 60); // 30 jours
        this.lastUsedAt = Instant.now();
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    public void updateLastSeen(String ip, String userAgent, String countryCode) {
        this.lastIp = ip;
        this.lastUserAgent = userAgent;
        this.lastCountryCode = countryCode;
        this.lastUsedAt = Instant.now();
    }
}
