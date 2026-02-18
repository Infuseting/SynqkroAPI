package fr.synqkro.api.common.repository;

import fr.synqkro.api.common.entity.EmailChangeTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface EmailChangeTokenRepository extends JpaRepository<EmailChangeTokenEntity, Long> {

    Optional<EmailChangeTokenEntity> findByToken(String token);

    Optional<EmailChangeTokenEntity> findByUserId(Long userId);

    void deleteByUserId(Long userId);

    void deleteByToken(String token);
}
