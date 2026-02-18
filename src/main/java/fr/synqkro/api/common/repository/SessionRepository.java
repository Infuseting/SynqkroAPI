package fr.synqkro.api.common.repository;

import fr.synqkro.api.common.entity.SessionEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface SessionRepository extends JpaRepository<SessionEntity, Long> {

    /**
     * Trouve toutes les sessions d'un utilisateur
     */
    List<SessionEntity> findByUserId(Long userId);

    /**
     * Trouve la session par refresh token ID
     */
    Optional<SessionEntity> findByRefreshTokenId(Long refreshTokenId);

    /**
     * Trouve toutes les sessions actives d'un utilisateur (ordonnées par récence)
     */
    @Query("SELECT s FROM SessionEntity s WHERE s.userId = :userId ORDER BY s.lastSeenAt DESC")
    List<SessionEntity> findAllActiveByUserId(@Param("userId") Long userId);

    /**
     * Trouve les sessions à haut risque pour un utilisateur
     */
    @Query("SELECT s FROM SessionEntity s WHERE s.userId = :userId AND s.riskScore >= :minScore ORDER BY s.riskScore DESC")
    List<SessionEntity> findHighRiskSessions(@Param("userId") Long userId, @Param("minScore") int minScore);

    /**
     * Trouve les sessions d'un utilisateur par pays
     */
    List<SessionEntity> findByUserIdAndCountryCode(Long userId, String countryCode);

    /**
     * Supprime toutes les sessions d'un utilisateur
     */
    @Modifying
    @Query("DELETE FROM SessionEntity s WHERE s.userId = :userId")
    void deleteByUserId(@Param("userId") Long userId);

    /**
     * Supprime une session par refresh token ID
     */
    @Modifying
    @Query("DELETE FROM SessionEntity s WHERE s.refreshTokenId = :refreshTokenId")
    void deleteByRefreshTokenId(@Param("refreshTokenId") Long refreshTokenId);

    /**
     * Supprime toutes les sessions sauf la courante
     */
    @Modifying
    @Query("DELETE FROM SessionEntity s WHERE s.userId = :userId AND s.id != :currentSessionId")
    void deleteAllExceptCurrent(@Param("userId") Long userId, @Param("currentSessionId") Long currentSessionId);

    /**
     * Compte les sessions actives d'un utilisateur dans la dernière heure
     */
    @Query("SELECT COUNT(s) FROM SessionEntity s WHERE s.userId = :userId AND s.lastSeenAt > :since")
    long countRecentSessions(@Param("userId") Long userId, @Param("since") Instant since);

    /**
     * Trouve les sessions avec impossible travel (multiples pays en peu de temps)
     */
    @Query("""
                SELECT s FROM SessionEntity s
                WHERE s.userId = :userId
                  AND s.lastSeenAt > :since
                ORDER BY s.lastSeenAt DESC
            """)
    List<SessionEntity> findRecentSessionsForTravelDetection(
            @Param("userId") Long userId,
            @Param("since") Instant since);
}
