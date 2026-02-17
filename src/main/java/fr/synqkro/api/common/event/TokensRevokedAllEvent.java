package fr.synqkro.api.common.event;

import java.time.Instant;
import java.util.List;

public record TokensRevokedAllEvent(
        long        userId,
        List<Long> tokenIds,
        Instant revokedAt
) {}