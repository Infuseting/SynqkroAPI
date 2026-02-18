package fr.synqkro.api.auth.service;

import fr.synqkro.api.common.entity.UserEntity;
import fr.synqkro.api.common.exception.ApiException;
import fr.synqkro.api.common.repository.UserRepository;
import fr.synqkro.api.common.service.EmailService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

/**
 * Service pour la gestion du reset et du changement de mot de passe.
 *
 * <h2>Politique de révocation des sessions</h2>
 * <ul>
 * <li><b>changePassword (oldPassword/newPassword)</b> : révoque toutes les
 * sessions
 * <em>sauf</em> la session courante — l'utilisateur reste connecté.</li>
 * <li><b>resetPasswordWithToken</b> : révoque <em>toutes</em> les sessions
 * (reset externe = déconnexion totale de sécurité).</li>
 * <li><b>resetPasswordWithTotp</b> : révoque <em>toutes</em> les sessions
 * (reset externe = déconnexion totale de sécurité).</li>
 * </ul>
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class PasswordResetService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;
    private final TotpService totpService;
    private final SessionService sessionService;

    private static final int RESET_TOKEN_LENGTH = 32;
    private static final long RESET_TOKEN_VALIDITY_HOURS = 1;

    /**
     * Demande un reset de mot de passe.
     * Si TOTP activé, renvoie un message indiquant qu'il faut utiliser TOTP.
     * Sinon, génère un token et envoie un email.
     */
    @Transactional
    public void requestReset(String email) {
        UserEntity user = userRepository.findByEmail(email).orElse(null);

        // Ne pas révéler si l'email existe ou non (sécurité)
        if (user == null) {
            log.info("Password reset requested for non-existent email: {}", email);
            return;
        }

        // Si TOTP activé, on ne peut pas reset par email — envoyer un email explicatif
        if (user.isTotpVerified()) {
            log.info("Password reset requested for user {} with TOTP enabled", user.getId());
            emailService.sendPasswordResetTotpRequired(user.getEmail(), user.getUsername());
            return;
        }

        // Générer token de reset
        String token = generateResetToken();
        Instant expiresAt = Instant.now().plusSeconds(RESET_TOKEN_VALIDITY_HOURS * 3600);

        // Sauvegarder token hashé
        user.setPasswordResetToken(passwordEncoder.encode(token));
        user.setPasswordResetTokenExpiresAt(expiresAt);
        userRepository.save(user);

        // Envoyer email avec token
        String resetUrl = "https://synqkro.fr/reset-password?token=" + token;
        emailService.sendPasswordReset(email, user.getUsername(), resetUrl, RESET_TOKEN_VALIDITY_HOURS + " heures");

        log.info("Password reset token generated for user {}", user.getId());
    }

    /**
     * Reset le mot de passe via token email OU via TOTP.
     *
     * @param token       token reçu par email (flow sans TOTP)
     * @param email       email de l'utilisateur (requis pour le flow TOTP)
     * @param totpCode    code TOTP ou recovery code (flow TOTP)
     * @param newPassword nouveau mot de passe
     */
    @Transactional
    public void resetPassword(String token, String newPassword, String email, String totpCode) {
        if (token != null && !token.isEmpty()) {
            resetPasswordWithToken(token, newPassword);
        } else if (totpCode != null && !totpCode.isEmpty()) {
            if (email == null || email.isBlank()) {
                throw new ApiException("EMAIL_REQUIRED_FOR_TOTP_RESET", HttpStatus.BAD_REQUEST);
            }
            resetPasswordWithTotp(email, totpCode, newPassword);
        } else {
            throw new ApiException("RESET_METHOD_REQUIRED", HttpStatus.BAD_REQUEST);
        }
    }

    /**
     * Reset avec token email.
     * Révoque <b>toutes</b> les sessions (déconnexion totale).
     */
    private void resetPasswordWithToken(String token, String newPassword) {
        UserEntity user = userRepository.findByValidPasswordResetToken(token, Instant.now())
                .orElseThrow(() -> new ApiException("INVALID_OR_EXPIRED_TOKEN", HttpStatus.UNAUTHORIZED));

        // Changer le mot de passe
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        user.setPasswordResetToken(null);
        user.setPasswordResetTokenExpiresAt(null);
        userRepository.save(user);

        // Révoquer TOUTES les sessions (reset externe = déconnexion totale)
        sessionService.revokeAllSessions(user.getId(), false, null);

        log.info("Password reset with token for user {} — all sessions revoked", user.getId());
    }

    /**
     * Reset avec code TOTP (si TOTP activé).
     * L'utilisateur s'identifie par email + code TOTP, puis change son mot de
     * passe.
     * Révoque <b>toutes</b> les sessions (déconnexion totale).
     *
     * @param email       email de l'utilisateur
     * @param totpCode    code TOTP à 6 chiffres ou recovery code
     * @param newPassword nouveau mot de passe
     */
    private void resetPasswordWithTotp(String email, String totpCode, String newPassword) {
        // Trouver l'utilisateur par email (message générique pour éviter l'énumération)
        UserEntity user = userRepository.findByEmail(email)
                .orElseThrow(() -> new ApiException("INVALID_CREDENTIALS", HttpStatus.UNAUTHORIZED));

        // Vérifier que le TOTP est bien activé sur ce compte
        if (!user.isTotpVerified() || user.getTotpSecret() == null) {
            throw new ApiException("TOTP_NOT_ENABLED", HttpStatus.BAD_REQUEST);
        }

        // Vérifier le code TOTP (accepte aussi les recovery codes)
        boolean valid = totpService.verify(user.getId(), totpCode);
        if (!valid) {
            log.warn("Invalid TOTP code during password reset for user {}", user.getId());
            throw new ApiException("INVALID_TOTP_CODE", HttpStatus.UNAUTHORIZED);
        }

        // Changer le mot de passe
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // Révoquer TOUTES les sessions (reset externe = déconnexion totale)
        sessionService.revokeAllSessions(user.getId(), false, null);

        log.info("Password reset with TOTP for user {} — all sessions revoked", user.getId());
    }

    /**
     * Changement de mot de passe authentifié (user connecté).
     * Révoque toutes les sessions <b>sauf</b> la session courante.
     *
     * @param userId           ID de l'utilisateur connecté
     * @param oldPassword      ancien mot de passe (vérification)
     * @param newPassword      nouveau mot de passe
     * @param currentSessionId ID de la session courante à conserver (extrait du
     *                         JWT)
     * @param request          requête HTTP pour extraire l'IP
     */
    @Transactional
    public void changePassword(Long userId, String oldPassword, String newPassword,
            Long currentSessionId, HttpServletRequest request) {
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new ApiException("USER_NOT_FOUND", HttpStatus.NOT_FOUND));

        // Vérifier l'ancien mot de passe
        if (!passwordEncoder.matches(oldPassword, user.getPasswordHash())) {
            throw new ApiException("INVALID_OLD_PASSWORD", HttpStatus.UNAUTHORIZED);
        }

        // Vérifier que le nouveau est différent
        if (oldPassword.equals(newPassword)) {
            throw new ApiException("NEW_PASSWORD_SAME_AS_OLD", HttpStatus.BAD_REQUEST);
        }

        // Changer le password
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);

        // Révoquer toutes les sessions SAUF la courante (l'utilisateur reste connecté)
        sessionService.revokeAllSessions(userId, currentSessionId != null, currentSessionId);

        log.info("Password changed for user {} — all other sessions revoked (kept session: {})",
                userId, currentSessionId);

        // Envoyer notification email avec IP réelle
        if (user.getEmail() != null) {
            String ip = extractIp(request);
            emailService.sendPasswordChanged(
                    user.getEmail(),
                    user.getUsername(),
                    java.time.ZonedDateTime.now()
                            .format(java.time.format.DateTimeFormatter.ofPattern("dd/MM/yyyy à HH:mm")),
                    ip,
                    "Unknown" // La géolocalisation IP nécessite un service externe (MaxMind GeoIP2)
            );
        }
    }

    /**
     * Extrait l'adresse IP réelle du client depuis la requête HTTP.
     * Supporte les proxies et load balancers via X-Forwarded-For.
     */
    private String extractIp(HttpServletRequest request) {
        if (request == null)
            return "Unknown";
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        String realIp = request.getHeader("X-Real-IP");
        if (realIp != null && !realIp.isBlank()) {
            return realIp.trim();
        }
        return request.getRemoteAddr();
    }

    /**
     * Génère un token de reset sécurisé.
     */
    private String generateResetToken() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[RESET_TOKEN_LENGTH];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /**
     * Vérifie si un token est valide (sans le consommer).
     */
    public boolean isValidToken(String token) {
        return userRepository.findByValidPasswordResetToken(token, Instant.now()).isPresent();
    }
}
