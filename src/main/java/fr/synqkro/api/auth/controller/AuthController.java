package fr.synqkro.api.auth.controller;

import fr.synqkro.api.auth.dto.request.LoginRequest;
import fr.synqkro.api.auth.dto.request.RegisterRequest;
import fr.synqkro.api.auth.dto.response.TokenResponse;
import fr.synqkro.api.auth.service.AuthService;
import fr.synqkro.api.common.dto.response.ApiResponse;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<TokenResponse>> register(@Valid @RequestBody RegisterRequest request, HttpServletResponse response) {
        TokenResponse tokenResponse = authService.register(request, response);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.success(tokenResponse));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<TokenResponse>> login(@Valid @RequestBody LoginRequest request, HttpServletResponse response) {
        TokenResponse tokenResponse = authService.login(request, response);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.success(tokenResponse));
    }
}
