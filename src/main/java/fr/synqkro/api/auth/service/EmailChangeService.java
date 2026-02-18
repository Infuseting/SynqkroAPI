package fr.synqkro.api.auth.service;

import fr.synqkro.api.common.entity.EmailChangeTokenEntity;
import fr.synqkro.api.common.repository.EmailChangeTokenRepository;
import fr.synqkro.api.common.entity.UserEntity;
import fr.synqkro.api.common.exception.ApiException;
import fr.synqkro.api.common.repository.UserRepository;
import fr.synqkro.api.common.service.EmailService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.Base64;

/**
 * Service pour gérer les changements d'email.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EmailChangeService {

    private final EmailChangeTokenRepository tokenRepository;
    private final UserRepository userRepository;
    private final EmailService emailService;
    private final SecureRandom secureRandom = new SecureRandom();

    @Value("${app.url}")
    private String appUrl;

    /**
     * Demande de changement d'email.
     * Génère un token et envoie un email de confirmation à l'adresse actuelle
     * (ancienne adresse) pour que l'utilisateur valide le changement depuis son
     * compte existant.
     */
    @Transactional
    public void requestEmailChange(Long userId, String newEmail) {
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new ApiException("USER_NOT_FOUND", HttpStatus.NOT_FOUND));

        // Vérifier que le nouvel email n'est pas déjà utilisé
        if (userRepository.existsByEmail(newEmail)) {
            throw new ApiException("EMAIL_ALREADY_EXISTS", HttpStatus.CONFLICT);
        }

        // Supprimer les anciens tokens pour cet utilisateur
        tokenRepository.findByUserId(userId).ifPresent(tokenRepository::delete);

        // Générer un token sécurisé
        String token = generateSecureToken();

        // Créer le token de changement d'email
        EmailChangeTokenEntity changeToken = EmailChangeTokenEntity.builder()
                .userId(userId)
                .newEmail(newEmail)
                .token(token)
                .build();

        tokenRepository.save(changeToken);

        // Envoyer l'email de confirmation à l'ANCIENNE adresse (sécurité :
        // l'utilisateur doit valider depuis son compte actuel)
        String confirmationUrl = appUrl + "/confirm-email-change?token=" + token;
        emailService.sendEmailChangeConfirmation(user.getEmail(), user.getUsername(), confirmationUrl);

        log.info("Email change requested for user {} to new email {}", userId, newEmail);
    }

    /**
     * Confirme le changement d'email avec le token.
     */
    @Transactional
    public void confirmEmailChange(String token) {
        EmailChangeTokenEntity changeToken = tokenRepository.findByToken(token)
                .orElseThrow(() -> new ApiException("INVALID_TOKEN", HttpStatus.BAD_REQUEST));

        if (changeToken.isExpired()) {
            tokenRepository.delete(changeToken);
            throw new ApiException("TOKEN_EXPIRED", HttpStatus.BAD_REQUEST);
        }

        UserEntity user = userRepository.findById(changeToken.getUserId())
                .orElseThrow(() -> new ApiException("USER_NOT_FOUND", HttpStatus.NOT_FOUND));

        // Vérifier à nouveau que l'email n'est pas pris
        if (userRepository.existsByEmail(changeToken.getNewEmail())) {
            throw new ApiException("EMAIL_ALREADY_EXISTS", HttpStatus.CONFLICT);
        }

        String oldEmail = user.getEmail();
        user.setEmail(changeToken.getNewEmail());
        userRepository.save(user);

        // Supprimer le token
        tokenRepository.delete(changeToken);

        // Envoyer un email de confirmation à l'ancienne et nouvelle adresse
        emailService.sendEmailChanged(changeToken.getNewEmail(), user.getUsername());
        if (oldEmail != null) {
            emailService.sendEmailChangedNotification(oldEmail, user.getUsername(), changeToken.getNewEmail());
        }

        log.info("Email changed for user {} from {} to {}", user.getId(), oldEmail, changeToken.getNewEmail());
    }

    private String generateSecureToken() {
        byte[] randomBytes = new byte[32];
        secureRandom.nextBytes(randomBytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
    }
}
