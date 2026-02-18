package fr.synqkro.api.common.repository;

import fr.synqkro.api.common.entity.TrustedDeviceEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface TrustedDeviceRepository extends JpaRepository<TrustedDeviceEntity, Long> {

    /**
     * Trouve un device par user et fingerprint
     */
    Optional<TrustedDeviceEntity> findByUserIdAndFingerprint(Long userId, String fingerprint);

    /**
     * Trouve tous les devices d'un utilisateur
     */
    List<TrustedDeviceEntity> findAllByUserId(Long userId);

    /**
     * Trouve tous les devices trusted d'un utilisateur
     */
    List<TrustedDeviceEntity> findByUserIdAndTrustedTrue(Long userId);

    /**
     * Trouve les devices expirés
     */
    @Query("SELECT d FROM TrustedDeviceEntity d WHERE d.expiresAt < :now")
    List<TrustedDeviceEntity> findExpiredDevices(@Param("now") Instant now);

    /**
     * Supprime les devices expirés (scheduled cleanup)
     */
    @Modifying
    @Query("DELETE FROM TrustedDeviceEntity d WHERE d.expiresAt < :now")
    int deleteExpired(@Param("now") Instant now);

    /**
     * Supprime tous les devices d'un utilisateur
     */
    @Modifying
    @Query("DELETE FROM TrustedDeviceEntity d WHERE d.userId = :userId")
    void deleteByUserId(@Param("userId") Long userId);

    /**
     * Compte les devices trusted d'un utilisateur
     */
    long countByUserIdAndTrustedTrue(Long userId);

    /**
     * Vérifie si un device est trusted pour un utilisateur
     */
    @Query("""
                SELECT CASE WHEN COUNT(d) > 0 THEN true ELSE false END
                FROM TrustedDeviceEntity d
                WHERE d.userId = :userId
                  AND d.fingerprint = :fingerprint
                  AND d.trusted = true
                  AND d.expiresAt > :now
            """)
    boolean isTrustedDevice(
            @Param("userId") Long userId,
            @Param("fingerprint") String fingerprint,
            @Param("now") Instant now);

    /**
     * Trouve les devices d'un utilisateur utilisés récemment
     */
    @Query("SELECT d FROM TrustedDeviceEntity d WHERE d.userId = :userId AND d.lastUsedAt > :since ORDER BY d.lastUsedAt DESC")
    List<TrustedDeviceEntity> findRecentlyUsedDevices(@Param("userId") Long userId, @Param("since") Instant since);
}
