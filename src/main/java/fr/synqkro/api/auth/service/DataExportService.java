package fr.synqkro.api.auth.service;

import fr.synqkro.api.common.entity.UserEntity;
import fr.synqkro.api.common.exception.ApiException;
import fr.synqkro.api.common.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.format.DateTimeFormatter;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Service pour l'export des données personnelles (RGPD).
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class DataExportService {

    private final UserRepository userRepository;
    private final SessionService sessionService;

    private static final DateTimeFormatter FORMATTER = DateTimeFormatter.ISO_INSTANT;

    /**
     * Génère un export ZIP contenant toutes les données personnelles de
     * l'utilisateur.
     * Conforme aux exigences RGPD article 20 (droit à la portabilité).
     */
    public byte[] exportUserData(Long userId) {
        UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new ApiException("USER_NOT_FOUND", HttpStatus.NOT_FOUND));

        try (ByteArrayOutputStream baos = new ByteArrayOutputStream();
                ZipOutputStream zos = new ZipOutputStream(baos)) {

            // 1. Données utilisateur (user.json)
            addJsonFile(zos, "user.json", generateUserJson(user));

            // 2. Sessions actives (sessions.json)
            var sessions = sessionService.listSessions(userId);
            addJsonFile(zos, "sessions.json", generateSessionsJson(sessions));

            // 3. README avec contexte
            addTextFile(zos, "README.txt", generateReadme(user));

            zos.finish();
            log.info("Data export generated for userId={}", userId);
            return baos.toByteArray();

        } catch (IOException e) {
            log.error("Failed to generate data export for userId={}", userId, e);
            throw new ApiException("EXPORT_FAILED", HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    private void addJsonFile(ZipOutputStream zos, String filename, String content) throws IOException {
        ZipEntry entry = new ZipEntry(filename);
        zos.putNextEntry(entry);
        zos.write(content.getBytes(StandardCharsets.UTF_8));
        zos.closeEntry();
    }

    private void addTextFile(ZipOutputStream zos, String filename, String content) throws IOException {
        addJsonFile(zos, filename, content);
    }

    private String generateUserJson(UserEntity user) {
        return String.format("""
                {
                  "id": %d,
                  "username": "%s",
                  "email": "%s",
                  "totpEnabled": %b,
                  "createdAt": "%s",
                  "updatedAt": "%s"
                }
                """,
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.isTotpEnabled(),
                user.getCreatedAt() != null ? FORMATTER.format(user.getCreatedAt()) : "null",
                user.getUpdatedAt() != null ? FORMATTER.format(user.getUpdatedAt()) : "null");
    }

    private String generateSessionsJson(java.util.List<fr.synqkro.api.common.entity.SessionEntity> sessions) {
        if (sessions.isEmpty()) {
            return "[]";
        }

        StringBuilder sb = new StringBuilder("[\n");
        for (int i = 0; i < sessions.size(); i++) {
            var session = sessions.get(i);
            sb.append(String.format("""
                    {
                      "id": %d,
                      "ip": "%s",
                      "userAgent": "%s",
                      "city": "%s",
                      "countryCode": "%s",
                      "createdAt": "%s",
                      "lastSeenAt": "%s"
                    }""",
                    session.getId(),
                    session.getIp(),
                    session.getUserAgent(),
                    session.getCity(),
                    session.getCountryCode(),
                    session.getCreatedAt() != null ? FORMATTER.format(session.getCreatedAt()) : "null",
                    session.getLastSeenAt() != null ? FORMATTER.format(session.getLastSeenAt()) : "null"));
            if (i < sessions.size() - 1) {
                sb.append(",\n");
            }
        }
        sb.append("\n]");
        return sb.toString();
    }

    private String generateReadme(UserEntity user) {
        return String.format("""
                Export de vos données personnelles - RGPD
                ==========================================

                Date de l'export: %s
                Utilisateur: %s

                Ce fichier ZIP contient toutes vos données personnelles stockées sur notre plateforme,
                conformément à l'article 20 du RGPD (droit à la portabilité des données).

                Contenu de l'archive:
                - user.json: Vos informations de profil
                - sessions.json: Historique de vos sessions actives
                - README.txt: Ce fichier

                Pour toute question, contactez: support@synqkro.fr
                """,
                java.time.Instant.now(),
                user.getUsername());
    }
}
