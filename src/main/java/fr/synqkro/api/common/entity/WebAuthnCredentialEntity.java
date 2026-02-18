package fr.synqkro.api.common.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;

@Entity
@Table(name = "webauthn_credentials", indexes = {
        @Index(name = "idx_webauthn_user_id", columnList = "user_id"),
        @Index(name = "idx_webauthn_credential_id", columnList = "credential_id", unique = true)
})
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class WebAuthnCredentialEntity {

    @Id
    @Column(nullable = false, updatable = false)
    private Long id; // Snowflake ID

    @Column(name = "user_id", nullable = false, updatable = false)
    private Long userId;

    @Column(name = "name", length = 100)
    private String name; // "YubiKey 5", "Touch ID - MacBook"

    @Lob
    @Column(name = "credential_id", nullable = false, unique = true)
    private byte[] credentialId; // ID unique de la credential WebAuthn

    @Lob
    @Column(name = "public_key", nullable = false)
    private byte[] publicKey; // Clé publique COSE

    @Column(name = "aaguid", length = 36)
    private String aaguid; // Authenticator GUID

    @Column(name = "sign_count", nullable = false)
    @Builder.Default
    private long signCount = 0; // Compteur de signatures (anti-clonage)

    @Column(name = "backup_eligible", nullable = false)
    @Builder.Default
    private boolean backupEligible = false; // true si backup possible (iCloud Keychain, etc.)

    @Column(name = "backup_state", nullable = false)
    @Builder.Default
    private boolean backupState = false; // true si actuellement backed up

    @Column(name = "transports", length = 255)
    private String transports; // USB, NFC, BLE, INTERNAL (comma-separated)

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "last_used_at")
    private Instant lastUsedAt;

    @PrePersist
    protected void onCreate() {
        if (createdAt == null) {
            createdAt = Instant.now();
        }
    }

    public void incrementSignCount() {
        this.signCount++;
        this.lastUsedAt = Instant.now();
    }

    /**
     * Vérifie si le signCount est valide (anti-clonage).
     * Si le nouveau signCount est inférieur à l'actuel, c'est potentiellement un
     * clone.
     */
    public boolean isValidSignCount(long newSignCount) {
        return newSignCount > this.signCount;
    }
}
