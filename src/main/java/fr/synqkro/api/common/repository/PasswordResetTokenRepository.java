package fr.synqkro.api.common.repository;

import fr.synqkro.api.common.entity.UserEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

/**
 * Repository pour la gestion des tokens de réinitialisation de mot de passe.
 *
 * <p>
 * Les tokens sont stockés directement sur {@link UserEntity}
 * (champs {@code passwordResetToken} et {@code passwordResetTokenExpiresAt}).
 * Ce repository expose les opérations de nettoyage nécessaires, notamment
 * lors de la suppression de compte (conformité RGPD).
 */
@Repository
public interface PasswordResetTokenRepository extends JpaRepository<UserEntity, Long> {

    /**
     * Efface le token de réinitialisation de mot de passe d'un utilisateur.
     * Utilisé lors de la suppression de compte pour anonymiser les données.
     *
     * @param userId l'identifiant de l'utilisateur
     */
    @Modifying
    @Transactional
    @Query("""
            UPDATE UserEntity u SET
              u.passwordResetToken         = null,
              u.passwordResetTokenExpiresAt = null
            WHERE u.id = :userId
            """)
    void deleteByUserId(@Param("userId") Long userId);
}
