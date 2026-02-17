package fr.synqkro.api.common.event;

import java.time.Instant;

public record TokenRevokedEvent(
        long    tokenId,
        Instant revokedAt
) {}