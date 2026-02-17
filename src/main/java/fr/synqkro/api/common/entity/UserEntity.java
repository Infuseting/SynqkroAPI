package fr.synqkro.api.common.entity;


import fr.synqkro.api.common.converter.EncryptedStringConverter;
import fr.synqkro.api.common.enums.UserStatus;
import jakarta.persistence.*;
import lombok.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(
        name = "users",
        indexes = {
                @Index(name = "idx_users_email",    columnList = "email",    unique = true),
                @Index(name = "idx_users_username", columnList = "username", unique = true)
        }
)
@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserEntity {

    @Id
    @Column(nullable = false, updatable = false)
    private Long id;

    @Column(nullable = false, unique = true, length = 32)
    private String username;

    @Column(nullable = false, unique = true, length = 254)
    private String email;

    @Column(name = "password_hash", nullable = false, length = 128)
    private String passwordHash;

    @Column(name = "avatar_key", length = 256)
    private String avatarKey;

    @Column(name = "email_verified", nullable = false)
    @Builder.Default
    private boolean emailVerified = false;

    @Column(name = "email_verify_token", length = 64)
    private String emailVerifyToken;

    @Column(name = "email_verify_token_expires_at")
    private Instant emailVerifyTokenExpiresAt;

    @Column(name = "pending_email", length = 254)
    private String pendingEmail;

    @Column(name = "pending_email_token", length = 64)
    private String pendingEmailToken;

    @Column(name = "pending_email_token_expires_at")
    private Instant pendingEmailTokenExpiresAt;

    @Convert(converter = EncryptedStringConverter.class)
    @Column(name = "totp_secret", length = 512)
    private String totpSecret;

    @Column(name = "totp_enabled", nullable = false)
    @Builder.Default
    private boolean totpEnabled = false;

    @Column(name = "totp_verified", nullable = false)
    @Builder.Default
    private boolean totpVerified = false;

    @ElementCollection(fetch = FetchType.LAZY)
    @CollectionTable(name = "user_totp_recovery_codes",joinColumns = @JoinColumn(name = "user_id"))
    @Column(name = "code_hash", length = 128)
    @Builder.Default
    private List<String> totpRecoveryCodes = new ArrayList<>();

    @Column(name = "password_reset_token", length = 64)
    private String passwordResetToken;

    @Column(name = "password_reset_token_expires_at")
    private Instant passwordResetTokenExpiresAt;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 16)
    @Builder.Default
    private UserStatus status = UserStatus.ACTIVE;

    @Column(name = "deleted_at")
    private Instant deletedAt;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @PrePersist
    protected void onCreate() {
        createdAt = Instant.now();
        updatedAt = Instant.now();
    }

    @PreUpdate
    protected void onUpdate() {
        updatedAt = Instant.now();
    }

    public boolean isAnonymized() {
        return deletedAt != null;
    }

    public boolean isTotpPending() {
        return totpSecret != null && !totpVerified;
    }
}