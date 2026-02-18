package fr.synqkro.api.common.exception;

import lombok.Getter;

/**
 * Exception levée lors de la détection d'une anomalie de session.
 * (Ex: changement radical de fingerprint = vol de token potentiel)
 */
@Getter
public class SessionAnomalyException extends RuntimeException {

    private final Long userId;
    private final String oldFingerprint;
    private final String newFingerprint;
    private final int riskScore;

    public SessionAnomalyException(Long userId, String oldFingerprint, String newFingerprint, int riskScore) {
        super("Session anomaly detected for user " + userId + " (risk score: " + riskScore + ")");
        this.userId = userId;
        this.oldFingerprint = oldFingerprint;
        this.newFingerprint = newFingerprint;
        this.riskScore = riskScore;
    }

    public SessionAnomalyException(String message, Long userId, int riskScore) {
        super(message);
        this.userId = userId;
        this.oldFingerprint = null;
        this.newFingerprint = null;
        this.riskScore = riskScore;
    }
}
