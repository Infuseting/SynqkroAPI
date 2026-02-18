package fr.synqkro.api.auth.controller;

import fr.synqkro.api.auth.dto.request.*;
import fr.synqkro.api.auth.dto.response.*;
import fr.synqkro.api.auth.service.AuthService;
import fr.synqkro.api.auth.service.TotpService;
import fr.synqkro.api.auth.service.PasswordResetService;
import fr.synqkro.api.auth.service.SessionService;
import fr.synqkro.api.common.dto.response.ApiResponse;
import fr.synqkro.api.common.provider.JwtTokenProvider;
import fr.synqkro.api.common.service.TrustedDeviceService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final AuthService authService;
    private final TotpService totpService;
    private final PasswordResetService passwordResetService;
    private final SessionService sessionService;
    private final TrustedDeviceService trustedDeviceService;
    private final JwtTokenProvider jwtTokenProvider;
    private final fr.synqkro.api.auth.service.EmailChangeService emailChangeService;
    private final fr.synqkro.api.auth.service.AccountDeletionService accountDeletionService;
    private final fr.synqkro.api.auth.service.DataExportService dataExportService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<TokenResponse>> register(@Valid @RequestBody RegisterRequest request,
            HttpServletResponse response) {
        TokenResponse tokenResponse = authService.register(request, response);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.success(tokenResponse));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<TokenResponse>> login(@Valid @RequestBody LoginRequest request,
            HttpServletResponse response, HttpServletRequest httpRequest) {
        TokenResponse tokenResponse = authService.login(request, response, httpRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body(ApiResponse.success(tokenResponse));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(HttpServletRequest httpRequest, HttpServletResponse response) {
        LogoutResponse logoutResponse = authService.logout(httpRequest, response);
        return ResponseEntity.ok(ApiResponse.success(null));
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<TokenResponse>> refresh(HttpServletRequest httpRequest,
            HttpServletResponse response) {
        TokenResponse tokenResponse = authService.refresh(httpRequest, response);
        return ResponseEntity.ok(ApiResponse.success(tokenResponse));
    }

    @GetMapping("/me")
    public ResponseEntity<ApiResponse<UserProfileResponse>> me(HttpServletRequest request) {
        UserProfileResponse profile = authService.getCurrentUser(request);
        return ResponseEntity.ok(ApiResponse.success(profile));
    }

    @PostMapping("/delete")
    public ResponseEntity<ApiResponse<Void>> deleteAccount(HttpServletRequest httpRequest,
            HttpServletResponse response) {
        DeleteResponse deleteResponse = authService.delete(httpRequest, response);
        return ResponseEntity.ok(ApiResponse.success(null));
    }

    @DeleteMapping("/delete")
    public ResponseEntity<ApiResponse<Void>> deleteAccount(Authentication auth,
            @Valid @RequestBody DeleteAccountRequest request, HttpServletResponse response) {
        Long userId = extractUserId(auth);
        accountDeletionService.deleteAccount(userId, request.password());

        authService.logout(null, response);

        return ResponseEntity.ok(ApiResponse.success(null));
    }

    @PostMapping("/export")
    public ResponseEntity<byte[]> exportUserData(Authentication auth) {
        Long userId = extractUserId(auth);
        byte[] zipData = dataExportService.exportUserData(userId);

        return ResponseEntity.ok()
                .header("Content-Type", "application/zip")
                .header("Content-Disposition", "attachment; filename=\"user-data-export.zip\"")
                .body(zipData);
    }

    @PostMapping("/totp/generate")
    public ResponseEntity<ApiResponse<TotpGenerateResponse>> generateTotp(Authentication auth) {
        Long userId = extractUserId(auth);
        TotpGenerateResponse response = totpService.generate(userId);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PostMapping("/totp/validate")
    public ResponseEntity<ApiResponse<Void>> validateTotp(Authentication auth,
            @Valid @RequestBody TotpValidateRequest request) {
        Long userId = extractUserId(auth);
        totpService.validate(userId, request.code());
        return ResponseEntity.ok(ApiResponse.success(null));
    }

    @PostMapping("/totp/recovery-codes")
    public ResponseEntity<ApiResponse<TotpRecoveryCodesResponse>> generateRecoveryCodes(Authentication auth) {
        Long userId = extractUserId(auth);
        TotpRecoveryCodesResponse response = totpService.generateRecoveryCodes(userId);
        return ResponseEntity.ok(ApiResponse.success(response));
    }

    @PostMapping("/totp/disable")
    public ResponseEntity<ApiResponse<Void>> disableTotp(Authentication auth,
            @Valid @RequestBody TotpDisableRequest request) {
        Long userId = extractUserId(auth);
        totpService.disable(userId, request.code());
        return ResponseEntity.ok(ApiResponse.success(null));
    }

    @PostMapping("/password/forgot")
    public ResponseEntity<ApiResponse<Void>> forgotPassword(@Valid @RequestBody PasswordForgotRequest request) {
        passwordResetService.requestReset(request.email());
        return ResponseEntity.ok(ApiResponse.success(null));
    }

    @PostMapping("/password/reset")
    public ResponseEntity<ApiResponse<Void>> resetPassword(@Valid @RequestBody PasswordResetRequest request) {
        passwordResetService.resetPassword(request.token(), request.newPassword(), request.email(), request.totpCode());
        return ResponseEntity.ok(ApiResponse.success(null));
    }

    @PostMapping("/password/change")
    public ResponseEntity<ApiResponse<Void>> changePassword(Authentication auth,
            @Valid @RequestBody PasswordChangeRequest request,
            HttpServletRequest httpRequest) {
        Long userId = extractUserId(auth);

        // Extraire le sessionId courant depuis le claim 'sid' du JWT pour garder la
        // session active
        Long currentSessionId = null;
        String authHeader = httpRequest.getHeader("Authorization");
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            try {
                Object sid = jwtTokenProvider.parseToken(authHeader.substring(7)).get("sid");
                if (sid != null)
                    currentSessionId = ((Number) sid).longValue();
            } catch (Exception ignored) {
                /* session inconnue, on revoque tout */ }
        }

        passwordResetService.changePassword(userId, request.oldPassword(), request.newPassword(),
                currentSessionId, httpRequest);
        return ResponseEntity.ok(ApiResponse.success(null));
    }

    @PostMapping("/email/change")
    public ResponseEntity<ApiResponse<Void>> changeEmail(Authentication auth,
            @Valid @RequestBody EmailChangeRequest request) {
        Long userId = extractUserId(auth);
        emailChangeService.requestEmailChange(userId, request.newEmail());
        return ResponseEntity.ok(ApiResponse.success(null));
    }

    @GetMapping("/email/confirm")
    public ResponseEntity<ApiResponse<Void>> confirmEmail(@RequestParam("token") String token) {
        emailChangeService.confirmEmailChange(token);
        return ResponseEntity.ok(ApiResponse.success(null));
    }

    @GetMapping("/sessions")
    public ResponseEntity<ApiResponse<SessionListResponse>> listSessions(Authentication auth) {
        Long userId = extractUserId(auth);
        var sessions = sessionService.listSessions(userId);

        // Import the nested DTO via the parent class
        var sessionDtos = sessions.stream()
                .map(session -> SessionDto.fromEntity(session,
                        false))
                .toList();

        return ResponseEntity.ok(ApiResponse.success(new SessionListResponse(sessionDtos)));
    }

    @DeleteMapping("/sessions/{sessionId}")
    public ResponseEntity<ApiResponse<Void>> revokeSession(Authentication auth, @PathVariable Long sessionId) {
        Long userId = extractUserId(auth);
        sessionService.revokeSession(userId, sessionId);
        return ResponseEntity.ok(ApiResponse.success(null));
    }

    @PostMapping("/sessions/revoke-all")
    public ResponseEntity<ApiResponse<Void>> revokeAllSessions(Authentication auth,
            @Valid @RequestBody RevokeAllSessionsRequest request, HttpServletRequest httpRequest) {
        Long userId = extractUserId(auth);

        Long currentSessionId = null;
        if (request.keepCurrent()) {
            String authHeader = httpRequest.getHeader("Authorization");
            if (authHeader != null && authHeader.startsWith("Bearer ")) {
                String jwt = authHeader.substring(7);
                try {
                    Object sid = jwtTokenProvider.parseToken(jwt).get("sid");
                    if (sid != null) {
                        currentSessionId = ((Number) sid).longValue();
                    }
                } catch (Exception ignored) {
                }
            }
        }

        sessionService.revokeAllSessions(userId, request.keepCurrent(), currentSessionId);
        return ResponseEntity.ok(ApiResponse.success(null));
    }

    @PostMapping("/devices/trust")
    public ResponseEntity<ApiResponse<Void>> trustDevice(Authentication auth, HttpServletRequest request,
            @Valid @RequestBody TrustDeviceRequest deviceRequest) {
        Long userId = extractUserId(auth);
        String fingerprint = request.getHeader("X-Fingerprint");
        var device = trustedDeviceService.findOrCreate(userId, fingerprint);
        trustedDeviceService.trustDevice(userId, device.getId(), deviceRequest.deviceName());

        return ResponseEntity.ok(ApiResponse.success(null));
    }

    @GetMapping("/devices")
    public ResponseEntity<ApiResponse<TrustedDeviceListResponse>> listDevices(Authentication auth) {
        Long userId = extractUserId(auth);
        var devices = trustedDeviceService.listTrustedDevices(userId);

        var deviceDtos = devices.stream()
                .map(TrustedDeviceDto::fromEntity)
                .toList();

        return ResponseEntity.ok(ApiResponse.success(new TrustedDeviceListResponse(deviceDtos)));
    }

    @DeleteMapping("/devices/{deviceId}")
    public ResponseEntity<ApiResponse<Void>> revokeDevice(Authentication auth, @PathVariable Long deviceId) {
        Long userId = extractUserId(auth);
        trustedDeviceService.revokeDevice(userId, deviceId);
        return ResponseEntity.ok(ApiResponse.success(null));
    }

    private Long extractUserId(Authentication auth) {
        if (auth == null || auth.getPrincipal() == null) {
            throw new IllegalStateException("User not authenticated");
        }
        return Long.valueOf(auth.getPrincipal().toString());
    }

}
