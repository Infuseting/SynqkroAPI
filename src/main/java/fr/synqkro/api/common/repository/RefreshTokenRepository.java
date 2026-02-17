package fr.synqkro.api.common.repository;

import fr.synqkro.api.common.entity.RefreshTokenEntity;
import fr.synqkro.api.common.entity.UserEntity;
import org.apache.catalina.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshTokenEntity, Long> {

    Optional<RefreshTokenEntity> findByTokenHash(String tokenHash);

    @Query("""
            SELECT t FROM RefreshTokenEntity t
            WHERE t.userId = :userId
              AND t.revokedAt IS NULL
              AND t.expiresAt > CURRENT_TIMESTAMP
            """)
    List<RefreshTokenEntity> findAllActiveByUserId(@Param("userId") Long userId);

    @Query("""
            SELECT t FROM RefreshTokenEntity t
            WHERE t.userId = :userId
              AND t.revokedAt IS NULL
              AND t.expiresAt > :now
            """)
    List<RefreshTokenEntity> findAllActiveByUserId(
            @Param("userId") Long userId,
            @Param("now")    Instant now
    );


    @Modifying
    @Query("""
            UPDATE RefreshTokenEntity t
            SET t.revokedAt = :now
            WHERE t.userId = :userId
              AND t.revokedAt IS NULL
            """)
    void revokeAllByUserId(
            @Param("userId") Long userId,
            @Param("now")    Instant now
    );


    @Modifying
    @Query("""
            DELETE FROM RefreshTokenEntity t
            WHERE t.expiresAt < :threshold
               OR t.revokedAt IS NOT NULL
            """)
    int deleteExpiredAndRevoked(@Param("threshold") Instant threshold);
}
