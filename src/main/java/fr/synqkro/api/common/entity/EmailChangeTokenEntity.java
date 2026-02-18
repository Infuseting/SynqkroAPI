package fr.synqkro.api.common.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

/**
 * Entity pour gérer les changements d'email en attente de confirmation.
 */
@Entity
@Table(name = "email_change_tokens", indexes = {
        @Index(name = "idx_email_change_user_id", columnList = "user_id"),
        @Index(name = "idx_email_change_token", columnList = "token", unique = true)
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class EmailChangeTokenEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private Long userId;

    @Column(name = "new_email", nullable = false, length = 255)
    private String newEmail;

    @Column(name = "token", nullable = false, unique = true, length = 64)
    private String token;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "expires_at", nullable = false)
    private Instant expiresAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
        if (expiresAt == null) {
            // Token valide 24h
            expiresAt = Instant.now().plusSeconds(24L * 60 * 60);
        }
    }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
}
