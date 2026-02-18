package fr.synqkro.api.auth.service;

import fr.synqkro.api.common.entity.UserEntity;
import fr.synqkro.api.common.exception.ApiException;
import fr.synqkro.api.common.repository.UserRepository;
import fr.synqkro.api.common.repository.EmailChangeTokenRepository;
import fr.synqkro.api.common.repository.PasswordResetTokenRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.util.UUID;

/**
 * Service pour la suppression et l'anonymisation de compte conformément au
 * RGPD.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AccountDeletionService {

    private final UserRepository userRepository;
    private final PasswordResetTokenRepository passwordResetTokenRepository;
    private final EmailChangeTokenRepository emailChangeTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final SessionService sessionService;

    /**
     * Supprime (anonymise) un compte utilisateur conformément au RGPD.
     * Les données personnelles sont remplacées par des valeurs anonymes.
     */
    @Transactional
    public void deleteAccount(Long userId, String password) {
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new ApiException("USER_NOT_FOUND", HttpStatus.NOT_FOUND));

        // Vérifier le mot de passe avant suppression
        if (!passwordEncoder.matches(password, user.getPasswordHash())) {
            throw new ApiException("INVALID_PASSWORD", HttpStatus.UNAUTHORIZED);
        }

        // Révoquer toutes les sessions
        sessionService.revokeAllSessions(userId, false, null);

        // Supprimer les tokens de reset de mot de passe
        passwordResetTokenRepository.deleteByUserId(userId);

        // Supprimer les tokens de changement d'email
        emailChangeTokenRepository.deleteByUserId(userId);

        // Anonymiser les données personnelles (conformité RGPD)
        String anonymousId = "deleted_" + UUID.randomUUID().toString().substring(0, 8);
        user.setUsername(anonymousId);
        user.setEmail(anonymousId + "@deleted.local");
        user.setPasswordHash(passwordEncoder.encode(UUID.randomUUID().toString())); // Password aléatoire
        user.setTotpSecret(null);
        user.setTotpEnabled(false);
        user.setRecoveryCodes(null);
        user.setDeleted(true);
        user.setDeletedAt(Instant.now());

        userRepository.save(user);

        log.info("Account deleted and anonymized: userId={}", userId);
    }
}
