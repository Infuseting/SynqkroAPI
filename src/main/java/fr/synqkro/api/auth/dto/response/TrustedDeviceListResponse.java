package fr.synqkro.api.auth.dto.response;

import java.util.List;


public record TrustedDeviceListResponse(
                List<TrustedDeviceDto> devices) {
}
