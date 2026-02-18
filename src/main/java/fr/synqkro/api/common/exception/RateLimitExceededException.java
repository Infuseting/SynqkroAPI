package fr.synqkro.api.common.exception;

import lombok.Getter;

/**
 * Exception custom pour rate limiting.
 * Contient le nombre de secondes avant retry.
 */
@Getter
public class RateLimitExceededException extends RuntimeException {

    private final long retryAfterSeconds;
    private final String key;

    public RateLimitExceededException(String key, long retryAfterSeconds) {
        super("Rate limit exceeded for: " + key + ". Retry after " + retryAfterSeconds + " seconds");
        this.key = key;
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public RateLimitExceededException(String message, String key, long retryAfterSeconds) {
        super(message);
        this.key = key;
        this.retryAfterSeconds = retryAfterSeconds;
    }
}
