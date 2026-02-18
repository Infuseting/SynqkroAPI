package fr.synqkro.api.auth.dto.request;

import jakarta.validation.constraints.NotBlank;


public record DeleteAccountRequest(
        @NotBlank(message = "Le mot de passe est requis")
        String password
) {
}
