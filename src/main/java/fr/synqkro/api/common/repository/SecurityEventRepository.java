package fr.synqkro.api.common.repository;

import fr.synqkro.api.common.entity.SecurityEventEntity;
import fr.synqkro.api.common.enums.SecurityEventType;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;

@Repository
public interface SecurityEventRepository extends JpaRepository<SecurityEventEntity, Long> {

        /**
         * Trouve tous les événements d'un utilisateur (paginés)
         */
        Page<SecurityEventEntity> findByUserIdOrderByCreatedAtDesc(Long userId, Pageable pageable);

        /**
         * Trouve les événements d'un utilisateur par type
         */
        List<SecurityEventEntity> findByUserIdAndType(Long userId, SecurityEventType type);

        /**
         * Compte les événements d'un type pour un utilisateur dans une période
         */
        @Query("""
                            SELECT COUNT(e) FROM SecurityEventEntity e
                            WHERE e.userId = :userId
                              AND e.type = :type
                              AND e.createdAt BETWEEN :start AND :end
                        """)
        long countByUserIdAndTypeBetween(
                        @Param("userId") Long userId,
                        @Param("type") SecurityEventType type,
                        @Param("start") Instant start,
                        @Param("end") Instant end);

        /**
         * Trouve les événements à haut risque pour un utilisateur
         */
        @Query("SELECT e FROM SecurityEventEntity e WHERE e.userId = :userId AND e.riskScore >= :minScore ORDER BY e.createdAt DESC")
        List<SecurityEventEntity> findHighRiskEvents(@Param("userId") Long userId, @Param("minScore") int minScore);

        /**
         * Trouve les événements récents d'un utilisateur
         */
        @Query("SELECT e FROM SecurityEventEntity e WHERE e.userId = :userId AND e.createdAt > :since ORDER BY e.createdAt DESC")
        List<SecurityEventEntity> findRecentEvents(@Param("userId") Long userId, @Param("since") Instant since);

        /**
         * Trouve les échecs de login récents pour une IP
         */
        @Query("""
                            SELECT e FROM SecurityEventEntity e
                            WHERE e.ip = :ip
                              AND e.type = 'LOGIN_FAILED'
                              AND e.createdAt > :since
                            ORDER BY e.createdAt DESC
                        """)
        List<SecurityEventEntity> findRecentLoginFailuresByIp(@Param("ip") String ip, @Param("since") Instant since);

        /**
         * Trouve les logins réussis depuis plusieurs pays pour détecter impossible
         * travel
         */
        @Query("""
                            SELECT e FROM SecurityEventEntity e
                            WHERE e.userId = :userId
                              AND e.type = 'LOGIN_SUCCESS'
                              AND e.createdAt > :since
                            ORDER BY e.createdAt DESC
                        """)
        List<SecurityEventEntity> findRecentLoginsForTravelDetection(@Param("userId") Long userId,
                        @Param("since") Instant since);

        /**
         * Compte les tentatives de login dans une période
         */
        @Query("""
                            SELECT COUNT(e) FROM SecurityEventEntity e
                            WHERE e.userId = :userId
                              AND e.type IN ('LOGIN_SUCCESS', 'LOGIN_FAILED')
                              AND e.createdAt > :since
                        """)
        long countLoginAttempts(@Param("userId") Long userId, @Param("since") Instant since);

        /**
         * Vérifie si un fingerprint a déjà été utilisé pour un login réussi par
         * l'utilisateur.
         * Note: Utilise LIKE car les détails sont stockés en JSON string.
         */
        @Query("""
                            SELECT COUNT(e) > 0 FROM SecurityEventEntity e
                            WHERE e.userId = :userId
                              AND e.type = 'LOGIN_SUCCESS'
                              AND e.details LIKE %:fingerprint%
                        """)
        boolean existsByUserIdAndDetailsContainingFingerprint(@Param("userId") Long userId,
                        @Param("fingerprint") String fingerprint);
}
