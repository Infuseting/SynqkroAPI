package fr.synqkro.api.common.repository;

import fr.synqkro.api.common.entity.WebAuthnCredentialEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface WebAuthnCredentialRepository extends JpaRepository<WebAuthnCredentialEntity, Long> {

    /**
     * Trouve une credential par son credentialId (utilisé lors de
     * l'authentification)
     */
    Optional<WebAuthnCredentialEntity> findByCredentialId(byte[] credentialId);

    /**
     * Trouve toutes les credentials d'un utilisateur
     */
    List<WebAuthnCredentialEntity> findAllByUserId(Long userId);

    /**
     * Compte les credentials d'un utilisateur
     */
    long countByUserId(Long userId);

    /**
     * Incrémente le sign counter et update last used
     */
    @Modifying
    @Query("UPDATE WebAuthnCredentialEntity w SET w.signCount = :newSignCount, w.lastUsedAt = CURRENT_TIMESTAMP WHERE w.id = :id")
    void incrementSignCount(@Param("id") Long id, @Param("newSignCount") long newSignCount);

    /**
     * Supprime toutes les credentials d'un utilisateur
     */
    @Modifying
    @Query("DELETE FROM WebAuthnCredentialEntity w WHERE w.userId = :userId")
    void deleteByUserId(@Param("userId") Long userId);

    /**
     * Vérifie si un utilisateur a au moins une credential WebAuthn
     */
    boolean existsByUserId(Long userId);

    /**
     * Trouve les credentials avec backup (iCloud Keychain, etc.)
     */
    List<WebAuthnCredentialEntity> findByUserIdAndBackupStateTrue(Long userId);
}
