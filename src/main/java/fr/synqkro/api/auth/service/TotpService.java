package fr.synqkro.api.auth.service;

import dev.samstevens.totp.code.*;
import dev.samstevens.totp.exceptions.QrGenerationException;
import dev.samstevens.totp.qr.QrData;
import dev.samstevens.totp.qr.QrDataFactory;
import dev.samstevens.totp.qr.QrGenerator;
import dev.samstevens.totp.secret.SecretGenerator;
import dev.samstevens.totp.time.SystemTimeProvider;
import dev.samstevens.totp.time.TimeProvider;
import fr.synqkro.api.auth.dto.response.TotpGenerateResponse;
import fr.synqkro.api.auth.dto.response.TotpRecoveryCodesResponse;
import fr.synqkro.api.common.entity.UserEntity;
import fr.synqkro.api.common.exception.ApiException;
import fr.synqkro.api.common.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * Service pour la gestion du TOTP/2FA (RFC 6238).
 * Utilise la librairie totp-spring-boot-starter.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class TotpService {

    private final UserRepository userRepository;
    private final SecretGenerator secretGenerator;
    private final QrDataFactory qrDataFactory;
    private final QrGenerator qrGenerator;
    private final PasswordEncoder passwordEncoder;
    private final CodeVerifier verifier;
    private final fr.synqkro.api.common.service.EmailService emailService;

    @Value("${security.totp.issuer:Synqkro}")
    private String issuer;

    @Value("${security.totp.recovery-codes-count:10}")
    private int recoveryCodesCount;

    private static final int RECOVERY_CODE_LENGTH = 8;
    private static final String RECOVERY_CODE_CHARS = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"; // Sans lettres ambiguës

    /**
     * Génère un nouveau secret TOTP et retourne le QR code URL.
     */
    @Transactional
    public TotpGenerateResponse generate(Long userId) {
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new ApiException("USER_NOT_FOUND", HttpStatus.NOT_FOUND));

        // Vérifier si TOTP déjà activé
        if (user.isTotpVerified()) {
            throw new ApiException("TOTP_ALREADY_ENABLED", HttpStatus.BAD_REQUEST);
        }

        // Générer nouveau secret
        String secret = secretGenerator.generate();

        // Créer QR code data
        QrData data = qrDataFactory.newBuilder()
                .label(user.getUsername())
                .secret(secret)
                .issuer(issuer)
                .build();

        // Générer OTP Auth URL pour QR code
        String otpauthUrl = data.getUri();

        // Sauvegarder secret (sera chiffré par EncryptedStringConverter)
        user.setTotpSecret(secret);
        user.setTotpVerified(false); // Pas encore vérifié
        userRepository.save(user);

        log.info("TOTP secret generated for user {}", userId);

        return new TotpGenerateResponse(secret, otpauthUrl);
    }

    /**
     * Valide le code TOTP et active le 2FA pour l'utilisateur.
     */
    @Transactional
    public void validate(Long userId, String code) {
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new ApiException("USER_NOT_FOUND", HttpStatus.NOT_FOUND));

        if (user.getTotpSecret() == null) {
            throw new ApiException("TOTP_NOT_GENERATED", HttpStatus.BAD_REQUEST);
        }

        if (user.isTotpVerified()) {
            throw new ApiException("TOTP_ALREADY_VERIFIED", HttpStatus.BAD_REQUEST);
        }

        // Vérifier le code
        if (!verifier.isValidCode(user.getTotpSecret(), code)) {
            throw new ApiException("INVALID_TOTP_CODE", HttpStatus.UNAUTHORIZED);
        }

        // Activer TOTP
        user.setTotpVerified(true);
        userRepository.save(user);

        log.info("TOTP validated and enabled for user {}", userId);

        // Envoyer notification par email
        if (user.getEmail() != null) {
            String enabledTime = java.time.ZonedDateTime.now()
                    .format(java.time.format.DateTimeFormatter.ofPattern("dd/MM/yyyy à HH:mm"));
            emailService.sendTotpEnabled(user.getEmail(), user.getUsername(), enabledTime);
        }
    }

    /**
     * Vérifie un code TOTP (utilisé lors du login).
     */
    public boolean verify(Long userId, String code) {
        if (code == null || code.isEmpty()) {
            return false;
        }

        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new ApiException("USER_NOT_FOUND", HttpStatus.NOT_FOUND));

        if (!user.isTotpVerified() || user.getTotpSecret() == null) {
            return false;
        }

        // D'abord essayer avec le code TOTP
        if (verifier.isValidCode(user.getTotpSecret(), code)) {
            return true;
        }

        // Si échec, essayer avec un recovery code
        return verifyRecoveryCode(userId, code);
    }

    /**
     * Génère des codes de récupération.
     */
    @Transactional
    public TotpRecoveryCodesResponse generateRecoveryCodes(Long userId) {
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new ApiException("USER_NOT_FOUND", HttpStatus.NOT_FOUND));

        if (!user.isTotpVerified()) {
            throw new ApiException("TOTP_NOT_ENABLED", HttpStatus.BAD_REQUEST);
        }

        List<String> codes = new ArrayList<>();
        Set<String> hashedCodes = new java.util.HashSet<>();

        for (int i = 0; i < recoveryCodesCount; i++) {
            String code = generateRecoveryCode();
            codes.add(code);
            // Hash le code avant de le stocker (comme un password)
            hashedCodes.add(passwordEncoder.encode(code));
        }

        user.setTotpRecoveryCodes(new ArrayList<>(hashedCodes));
        userRepository.save(user);

        log.info("Generated {} recovery codes for user {}", recoveryCodesCount, userId);

        return new TotpRecoveryCodesResponse(codes);
    }

    /**
     * Vérifie et consomme un recovery code (usage unique).
     */
    @Transactional
    public boolean verifyRecoveryCode(Long userId, String code) {
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new ApiException("USER_NOT_FOUND", HttpStatus.NOT_FOUND));

        if (user.getTotpRecoveryCodes() == null || user.getTotpRecoveryCodes().isEmpty()) {
            return false;
        }

        // Chercher le code hashé qui correspond
        for (String hashedCode : new ArrayList<>(user.getTotpRecoveryCodes())) {
            if (passwordEncoder.matches(code, hashedCode)) {
                // Code trouvé ! Le retirer (usage unique)
                user.getTotpRecoveryCodes().remove(hashedCode);
                userRepository.save(user);

                log.warn("Recovery code used for user {}. Remaining codes: {}",
                        userId, user.getTotpRecoveryCodes().size());

                return true;
            }
        }

        return false;
    }

    /**
     * Désactive le TOTP après vérification du code.
     */
    @Transactional
    public void disable(Long userId, String code) {
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new ApiException("USER_NOT_FOUND", HttpStatus.NOT_FOUND));

        if (!user.isTotpVerified()) {
            throw new ApiException("TOTP_NOT_ENABLED", HttpStatus.BAD_REQUEST);
        }

        // Vérifier le code avant de désactiver
        if (!verify(userId, code)) {
            throw new ApiException("INVALID_TOTP_CODE", HttpStatus.UNAUTHORIZED);
        }

        // Désactiver et nettoyer
        user.setTotpSecret(null);
        user.setTotpVerified(false);
        user.setTotpRecoveryCodes(null);
        userRepository.save(user);

        log.info("TOTP disabled for user {}", userId);

        // Envoyer notification par email
        if (user.getEmail() != null) {
            String disabledTime = java.time.ZonedDateTime.now()
                    .format(java.time.format.DateTimeFormatter.ofPattern("dd/MM/yyyy à HH:mm"));
            emailService.sendTotpDisabled(
                    user.getEmail(),
                    user.getUsername(),
                    disabledTime,
                    "Unknown" // TODO: Get IP from request context
            );
        }
    }

    /**
     * Génère un code de récup alphanumérique de 8 caractères.
     */
    private String generateRecoveryCode() {
        SecureRandom random = new SecureRandom();
        StringBuilder code = new StringBuilder(RECOVERY_CODE_LENGTH);

        for (int i = 0; i < RECOVERY_CODE_LENGTH; i++) {
            int index = random.nextInt(RECOVERY_CODE_CHARS.length());
            code.append(RECOVERY_CODE_CHARS.charAt(index));
        }

        return code.toString();
    }
}
