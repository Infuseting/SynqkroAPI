package fr.synqkro.api.auth.dto.request;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record TrustDeviceRequest(
                @NotBlank(message = "DEVICE_NAME_REQUIRED")
                @Size(min = 1, max = 100, message = "DEVICE_NAME_INVALID_LENGTH")
                String deviceName
) {
}
