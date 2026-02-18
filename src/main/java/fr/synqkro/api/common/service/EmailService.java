package fr.synqkro.api.common.service;

import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;
import org.thymeleaf.TemplateEngine;
import org.thymeleaf.context.Context;

import java.util.Map;

/**
 * Service d'envoi d'emails avec templates HTML/CSS professionnels.
 * Utilise Thymeleaf pour le rendu des templates.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EmailService {

    private final JavaMailSender mailSender;
    private final TemplateEngine templateEngine;

    @Value("${spring.mail.from:noreply@synqkro.fr}")
    private String fromEmail;

    @Value("${app.name:Synqkro}")
    private String appName;

    @Value("${app.url:https://synqkro.fr}")
    private String appUrl;

    // ==========================================
    // Public API - Email Types
    // ==========================================

    /**
     * Email de bienvenue après inscription
     */
    public void sendWelcomeEmail(String to, String username, String confirmationUrl) {
        Map<String, Object> variables = Map.of(
                "username", username,
                "confirmationUrl", confirmationUrl,
                "appName", appName,
                "appUrl", appUrl);
        sendTemplatedEmail(to, "Bienvenue sur " + appName, "welcome", variables);
    }

    /**
     * Email de confirmation d'adresse email
     */
    public void sendEmailConfirmation(String to, String username, String confirmationUrl) {
        Map<String, Object> variables = Map.of(
                "username", username,
                "confirmationUrl", confirmationUrl,
                "appName", appName,
                "appUrl", appUrl);
        sendTemplatedEmail(to, "Confirmez votre adresse email", "email-confirmation", variables);
    }

    /**
     * Email de réinitialisation de mot de passe
     */
    public void sendPasswordReset(String to, String username, String resetUrl, String expiresIn) {
        Map<String, Object> variables = Map.of(
                "username", username,
                "resetUrl", resetUrl,
                "expiresIn", expiresIn,
                "appName", appName,
                "appUrl", appUrl);
        sendTemplatedEmail(to, "Réinitialisation de votre mot de passe", "password-reset", variables);
    }

    /**
     * Email informant l'utilisateur que le reset par email est impossible car TOTP
     * est activé.
     * L'utilisateur doit utiliser son application d'authentification pour
     * réinitialiser son mot de passe.
     */
    public void sendPasswordResetTotpRequired(String to, String username) {
        Map<String, Object> variables = Map.of(
                "username", username,
                "appName", appName,
                "appUrl", appUrl);
        sendTemplatedEmail(to, "Réinitialisation de mot de passe — Authentification requise",
                "password-reset-totp-required", variables);
    }

    /**
     * Email de confirmation de changement de mot de passe
     */
    public void sendPasswordChanged(String to, String username, String changeTime, String ipAddress, String location) {
        Map<String, Object> variables = Map.of(
                "username", username,
                "changeTime", changeTime,
                "ipAddress", ipAddress,
                "location", location,
                "appName", appName,
                "appUrl", appUrl);
        sendTemplatedEmail(to, "Votre mot de passe a été modifié", "password-changed", variables);
    }

    /**
     * Email d'alerte de sécurité (anomalie de session)
     */
    public void sendSessionAnomaly(String to, String username, String ipAddress, String location,
            String userAgent, int riskScore, String sessionUrl) {
        Map<String, Object> variables = Map.of(
                "username", username,
                "ipAddress", ipAddress,
                "location", location,
                "userAgent", userAgent,
                "riskScore", riskScore,
                "sessionUrl", sessionUrl,
                "appName", appName,
                "appUrl", appUrl);
        sendTemplatedEmail(to, "⚠️ Activité suspecte détectée", "session-anomaly", variables);
    }

    /**
     * Email de confirmation d'activation TOTP
     */
    public void sendTotpEnabled(String to, String username, String enabledTime) {
        Map<String, Object> variables = Map.of(
                "username", username,
                "enabledTime", enabledTime,
                "appName", appName,
                "appUrl", appUrl);
        sendTemplatedEmail(to, "Authentification à deux facteurs activée", "totp-enabled", variables);
    }

    /**
     * Email de notification de désactivation TOTP
     */
    public void sendTotpDisabled(String to, String username, String disabledTime, String ipAddress) {
        Map<String, Object> variables = Map.of(
                "username", username,
                "disabledTime", disabledTime,
                "ipAddress", ipAddress,
                "appName", appName,
                "appUrl", appUrl);
        sendTemplatedEmail(to, "Authentification à deux facteurs désactivée", "totp-disabled", variables);
    }

    /**
     * Email de notification de nouvel appareil de confiance
     */
    public void sendTrustedDeviceAdded(String to, String username, String deviceName,
            String ipAddress, String location, String addedTime) {
        Map<String, Object> variables = Map.of(
                "username", username,
                "deviceName", deviceName,
                "ipAddress", ipAddress,
                "location", location,
                "addedTime", addedTime,
                "appName", appName,
                "appUrl", appUrl);
        sendTemplatedEmail(to, "Nouvel appareil de confiance ajouté", "trusted-device-added", variables);
    }

    /**
     * Email de nouvelle connexion depuis un appareil inconnu
     */
    public void sendNewLoginAlert(String to, String username, String ipAddress, String location,
            String userAgent, String loginTime) {
        Map<String, Object> variables = Map.of(
                "username", username,
                "ipAddress", ipAddress,
                "location", location,
                "userAgent", userAgent,
                "loginTime", loginTime,
                "appName", appName,
                "appUrl", appUrl);
        sendTemplatedEmail(to, "Nouvelle connexion détectée", "new-login", variables);
    }

    /**
     * Email de demande de changement d'adresse email
     */
    public void sendEmailChangeConfirmation(String to, String username, String confirmationUrl) {
        Map<String, Object> variables = Map.of(
                "username", username,
                "confirmationUrl", confirmationUrl,
                "appName", appName,
                "appUrl", appUrl);
        sendTemplatedEmail(to, "Confirmez votre nouvelle adresse email", "email-change-confirmation", variables);
    }

    /**
     * Email de confirmation du changement d'adresse (envoyé à la nouvelle adresse)
     */
    public void sendEmailChanged(String to, String username) {
        Map<String, Object> variables = Map.of(
                "username", username,
                "appName", appName,
                "appUrl", appUrl);
        sendTemplatedEmail(to, "Votre adresse email a été modifiée", "email-changed", variables);
    }

    /**
     * Email de notification du changement d'adresse (envoyé à l'ancienne adresse)
     */
    public void sendEmailChangedNotification(String to, String username, String newEmail) {
        Map<String, Object> variables = Map.of(
                "username", username,
                "newEmail", newEmail,
                "appName", appName,
                "appUrl", appUrl);
        sendTemplatedEmail(to, "Votre adresse email a été modifiée", "email-changed-notification", variables);
    }

    // ==========================================
    // Template Engine
    // ==========================================

    /**
     * Envoie un email avec template Thymeleaf
     */
    private void sendTemplatedEmail(String to, String subject, String templateName, Map<String, Object> variables) {
        try {
            // Créer le contexte Thymeleaf
            Context context = new Context();
            context.setVariables(variables);

            // Rendre le template
            String htmlContent = templateEngine.process("emails/" + templateName, context);

            // Envoyer l'email
            sendHtmlEmail(to, subject, htmlContent);

            log.info("Email sent successfully: {} to {}", templateName, to);

        } catch (Exception e) {
            log.error("Failed to send email: {} to {}", templateName, to, e);
            // Ne pas propager l'erreur pour ne pas bloquer l'application
        }
    }

    /**
     * Envoie un email HTML
     */
    private void sendHtmlEmail(String to, String subject, String htmlContent) throws MessagingException {
        MimeMessage message = mailSender.createMimeMessage();
        MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

        helper.setFrom(fromEmail);
        helper.setTo(to);
        helper.setSubject(subject);
        helper.setText(htmlContent, true);

        mailSender.send(message);
    }
}
