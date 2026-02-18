package fr.synqkro.api.common.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Builder;

import java.time.Instant;
import java.util.Map;

/**
 * DTO pour représenter une erreur dans les réponses API.
 * Utilisé dans ApiResponse pour le champ error.
 */
@Builder
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ErrorDto(
        String code,
        String message,
        @Builder.Default Instant timestamp,
        String path,
        Map<String, String> details) {
    /**
     * Constructeur simplifié pour erreurs basiques.
     */
    public ErrorDto(String code, String message) {
        this(code, message, Instant.now(), null, null);
    }

    /**
     * Constructeur avec path.
     */
    public ErrorDto(String code, String message, String path) {
        this(code, message, Instant.now(), path, null);
    }

    /**
     * Constructeur complet avec timestamp par défaut.
     */
    public ErrorDto(String code, String message, Instant timestamp, String path, Map<String, String> details) {
        this.code = code;
        this.message = message;
        this.timestamp = timestamp != null ? timestamp : Instant.now();
        this.path = path;
        this.details = details;
    }
}
