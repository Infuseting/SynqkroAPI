package fr.synqkro.api.auth.dto.response;

import java.util.List;

public record SessionListResponse(
                List<SessionDto> sessions
) {
}
