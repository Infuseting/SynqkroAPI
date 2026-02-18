package fr.synqkro.api.common.entity;

import fr.synqkro.api.common.enums.SecurityEventType;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "security_events", indexes = {
        @Index(name = "idx_security_events_user_id", columnList = "user_id"),
        @Index(name = "idx_security_events_type", columnList = "type"),
        @Index(name = "idx_security_events_created_at", columnList = "created_at"),
        @Index(name = "idx_security_events_user_type_created", columnList = "user_id,type,created_at")
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityEventEntity {

    @Id
    @Column(nullable = false, updatable = false)
    private Long id; // Snowflake ID

    @Column(name = "user_id", nullable = false, updatable = false)
    private Long userId;

    @Enumerated(EnumType.STRING)
    @Column(name = "type", nullable = false, length = 50)
    private SecurityEventType type;

    @Column(name = "ip", length = 45)
    private String ip;

    @Column(name = "user_agent", length = 512)
    private String userAgent;

    @Column(name = "country_code", length = 2)
    private String countryCode;

    @Column(name = "city", length = 100)
    private String city;

    @Column(name = "risk_score")
    private Integer riskScore;

    @Column(name = "details", columnDefinition = "TEXT")
    private String details; // JSON avec détails spécifiques

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }

    public boolean isHighRiskEvent() {
        return riskScore != null && riskScore >= 50;
    }

    public boolean isCriticalEvent() {
        return riskScore != null && riskScore >= 75;
    }
}
