package fr.synqkro.api.common.event;

import java.time.Instant;

public record SessionAnomalyEvent(
        long    userId,
        String  storedIp,
        String  incomingIp,
        String  storedUserAgent,
        String  incomingUserAgent,
        Instant detectedAt
) {
    public SessionAnomalyEvent(long userId, String storedIp, String incomingIp,
                               String storedUserAgent, String incomingUserAgent) {
        this(userId, storedIp, incomingIp, storedUserAgent, incomingUserAgent, Instant.now());
    }
}
