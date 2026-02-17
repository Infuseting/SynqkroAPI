package fr.synqkro.api.common.repository;

import fr.synqkro.api.common.entity.UserEntity;
import org.apache.catalina.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Long> {

    @Query("""
            SELECT u FROM UserEntity u
            WHERE (lower(u.email)    = lower(:identifier)
               OR  lower(u.username) = lower(:identifier))
              AND  u.status != 'ANONYMIZED'
            """)
    Optional<UserEntity> findByEmailOrUsername(@Param("identifier") String identifier);

    @Query("""
            SELECT u FROM UserEntity u
            WHERE lower(u.email) = lower(:email)
              AND u.status != 'ANONYMIZED'
            """)
    Optional<UserEntity> findByEmail(@Param("email") String email);


    @Query("SELECT COUNT(u) > 0 FROM UserEntity u WHERE lower(u.email) = lower(:email)")
    boolean existsByEmail(@Param("email" ) String email);

    @Query("SELECT COUNT(u) > 0 FROM UserEntity u WHERE lower(u.username) = lower(:username)")
    boolean existsByUsername(@Param("username") String username);


    @Query("""
            SELECT u FROM UserEntity u
            WHERE u.emailVerifyToken = :token
              AND u.emailVerifyTokenExpiresAt > :now
              AND u.emailVerified = false
            """)
    Optional<UserEntity> findByValidEmailVerifyToken(
            @Param("token") String token,
            @Param("now")   Instant now
    );


    @Query("""
            SELECT u FROM UserEntity u
            WHERE u.pendingEmailToken = :token
              AND u.pendingEmailTokenExpiresAt > :now
            """)
    Optional<UserEntity> findByValidPendingEmailToken(
            @Param("token") String token,
            @Param("now")   Instant now
    );


    @Query("""
            SELECT u FROM UserEntity u
            WHERE u.passwordResetToken = :token
              AND u.passwordResetTokenExpiresAt > :now
              AND u.status = 'ACTIVE'
            """)
    Optional<UserEntity> findByValidPasswordResetToken(
            @Param("token") String token,
            @Param("now")   Instant now
    );


    @Modifying
    @Query("""
            UPDATE UserEntity u SET
              u.username                    = :anonymousUsername,
              u.email                       = :anonymousEmail,
              u.passwordHash                = :randomHash,
              u.avatarKey                   = null,
              u.emailVerified               = false,
              u.emailVerifyToken            = null,
              u.pendingEmail                = null,
              u.pendingEmailToken           = null,
              u.totpSecret                  = null,
              u.totpEnabled                 = false,
              u.totpVerified                = false,
              u.passwordResetToken          = null,
              u.status                      = 'ANONYMIZED',
              u.deletedAt                   = :now,
              u.updatedAt                   = :now
            WHERE u.id = :userId
            """)
    void anonymizeUser(
            @Param("userId")            Long userId,
            @Param("anonymousUsername") String anonymousUsername,
            @Param("anonymousEmail")    String anonymousEmail,
            @Param("randomHash")        String randomHash,
            @Param("now")               Instant now
    );



}
