package fr.synqkro.api.auth.service;

import fr.synqkro.api.auth.dto.internal.TokenValidation;
import fr.synqkro.api.auth.dto.request.LoginRequest;
import fr.synqkro.api.auth.dto.request.RegisterRequest;
import fr.synqkro.api.auth.dto.response.DeleteResponse;
import fr.synqkro.api.auth.dto.response.LogoutResponse;
import fr.synqkro.api.auth.dto.response.TokenResponse;
import fr.synqkro.api.auth.dto.response.UserProfileResponse;
import fr.synqkro.api.common.entity.RefreshTokenEntity;
import fr.synqkro.api.common.entity.UserEntity;
import fr.synqkro.api.common.exception.ApiException;
import fr.synqkro.api.common.repository.RefreshTokenRepository;
import fr.synqkro.api.common.repository.UserRepository;
import fr.synqkro.api.common.util.SnowflakeIDGenerator;
import fr.synqkro.api.common.util.UserDataGenerator;
import fr.synqkro.api.common.provider.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Cookie;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

/**
 * Service principal d'authentification.
 *
 * <p>
 * Gère l'ensemble du cycle de vie des sessions utilisateur :
 * inscription, connexion, déconnexion, rafraîchissement de token et suppression
 * de compte.
 * Utilise un système de double-token (access token JWT + refresh token opaque)
 * avec
 * rotation automatique pour prévenir le vol de session.
 *
 * <p>
 * <b>Flux d'authentification :</b>
 * <ol>
 * <li>L'utilisateur s'inscrit ou se connecte → un access token (15 min) et un
 * refresh
 * token (30 jours) sont émis.</li>
 * <li>Le refresh token est stocké en cookie
 * HttpOnly/Secure/SameSite=Strict.</li>
 * <li>À l'expiration de l'access token, le client appelle {@code /auth/refresh}
 * pour
 * obtenir un nouveau pair de tokens (token rotation).</li>
 * <li>Lors du logout, le refresh token est révoqué côté serveur.</li>
 * </ol>
 *
 * @see TokenService
 * @see fr.synqkro.api.common.provider.JwtTokenProvider
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;
    private final SnowflakeIDGenerator snowflake;
    private final RefreshTokenRepository refreshTokenRepository;
    private final JwtTokenProvider jwtTokenProvider;
    private final fr.synqkro.api.common.service.EmailService emailService;
    private final fr.synqkro.api.common.service.RiskScoreService riskScoreService;
    private final fr.synqkro.api.common.service.GeoLocationService geoLocationService;

    @Value("${app.url}")
    private String appUrl;

    private static final int EMAIL_VERIFY_TOKEN_BYTES = 32;
    private static final long EMAIL_VERIFY_TOKEN_VALIDITY_HOURS = 24;

    /**
     * Inscrit un nouvel utilisateur et émet une paire de tokens.
     *
     * <p>
     * Vérifie l'unicité de l'email et du nom d'utilisateur avant la création.
     * Le mot de passe est haché avec BCrypt. Un email de bienvenue avec lien de
     * confirmation est envoyé automatiquement.
     *
     * @param request  les données d'inscription (username, email, password)
     * @param response la réponse HTTP pour y déposer le cookie refreshToken
     * @return un {@link TokenResponse} contenant l'access token JWT
     * @throws ApiException {@code 409 CONFLICT} si l'email ou le username est déjà
     *                      utilisé
     */
    @Transactional
    public TokenResponse register(RegisterRequest request, HttpServletResponse response) {

        if (userRepository.existsByEmail(request.email())) {
            throw new ApiException("EMAIL_ALREADY_USED", HttpStatus.CONFLICT);
        }
        if (userRepository.existsByUsername(request.username())) {
            throw new ApiException("USERNAME_ALREADY_TAKEN", HttpStatus.CONFLICT);
        }

        UserEntity user = UserEntity.builder()
                .id(snowflake.nextId())
                .username(request.username())
                .email(request.email())
                .passwordHash(passwordEncoder.encode(request.password()))
                .emailVerified(false)
                .createdAt(Instant.now())
                .build();

        userRepository.save(user);
        log.info("New user registered: id={}", user.getId());

        // Générer et stocker le token de confirmation email
        String emailVerifyToken = generateEmailVerifyToken();
        user.setEmailVerifyToken(emailVerifyToken);
        user.setEmailVerifyTokenExpiresAt(Instant.now().plusSeconds(EMAIL_VERIFY_TOKEN_VALIDITY_HOURS * 3600));
        userRepository.save(user);

        // Envoyer email de bienvenue avec lien de confirmation
        String confirmationUrl = appUrl + "/confirm-email?token=" + emailVerifyToken;
        emailService.sendWelcomeEmail(user.getEmail(), user.getUsername(), confirmationUrl);

        return tokenService.issueTokens(user, response);
    }

    /**
     * Authentifie un utilisateur et émet une paire de tokens.
     *
     * <p>
     * Accepte un email ou un nom d'utilisateur. Le message d'erreur est
     * volontairement
     * générique ({@code INVALID_CREDENTIALS}) pour ne pas révéler si l'email
     * existe.
     *
     * @param request     les identifiants de connexion (usernameOrEmail, password,
     *                    totpCode optionnel)
     * @param response    la réponse HTTP pour y déposer le cookie refreshToken
     * @param httpRequest la requête HTTP pour l'analyse de risque (IP, UA)
     * @return un {@link TokenResponse} contenant l'access token JWT
     * @throws ApiException {@code 401 UNAUTHORIZED} si les identifiants sont
     *                      invalides
     * @throws ApiException {@code 403 FORBIDDEN} si le login est bloqué pour risque
     *                      critique
     */
    @Transactional
    public TokenResponse login(LoginRequest request, HttpServletResponse response, HttpServletRequest httpRequest) {

        UserEntity user = userRepository
                .findByEmailOrUsername(request.usernameOrEmail())
                .orElseThrow(() -> new ApiException("INVALID_CREDENTIALS", HttpStatus.UNAUTHORIZED));

        if (!passwordEncoder.matches(request.password(), user.getPasswordHash())) {
            throw new ApiException("INVALID_CREDENTIALS", HttpStatus.UNAUTHORIZED);
        }

        // --- Analyse de risque ---
        String ip = (httpRequest != null) ? getClientIp(httpRequest) : "127.0.0.1";
        String country = geoLocationService.getCountryCode(ip);
        String city = geoLocationService.getCity(ip);
        String userAgent = (httpRequest != null) ? httpRequest.getHeader("User-Agent") : "Unknown";
        String fingerprint = (httpRequest != null) ? httpRequest.getHeader("X-Fingerprint") : null;

        var context = fr.synqkro.api.common.service.RiskScoreService.LoginContext.builder()
                .userId(user.getId())
                .ip(ip)
                .countryCode(country)
                .city(city)
                .userAgent(userAgent)
                .fingerprint(fingerprint)
                .request(httpRequest)
                .build();

        int riskScore = riskScoreService.calculateRiskScore(context);

        if (riskScoreService.shouldBlockLogin(riskScore)) {
            log.warn("Login blocked for user {} due to CRITICAL risk score: {}", user.getId(), riskScore);
            throw new ApiException("LOGIN_BLOCKED_RISK", HttpStatus.FORBIDDEN);
        }

        if (riskScoreService.requiresAdditionalMfa(riskScore)) {
            // TODO: Si le user n'a pas TOTP activé, forcer une vérification par email ou
            // bloquer
            // Pour l'instant, on log juste le warning si TOTP n'est pas fourni
            if (!user.isTotpVerified() && (request.totpCode() == null || request.totpCode().isEmpty())) {
                log.warn("High risk login for user {} (score {}) but no MFA available/provided", user.getId(),
                        riskScore);
            }
        }
        // -------------------------

        return tokenService.issueTokens(user, response);
    }

    private String getClientIp(HttpServletRequest request) {
        if (request == null)
            return "127.0.0.1";
        String xfHeader = request.getHeader("X-Forwarded-For");
        if (xfHeader == null) {
            return request.getRemoteAddr();
        }
        return xfHeader.split(",")[0];
    }

    /**
     * Déconnecte l'utilisateur en révoquant son refresh token.
     *
     * <p>
     * Le cookie {@code refreshToken} est supprimé côté client via un Set-Cookie
     * avec {@code Max-Age=0}. La révocation côté serveur empêche la réutilisation
     * du token même s'il est intercepté.
     *
     * @param httpRequest la requête HTTP contenant le cookie refreshToken
     * @param response    la réponse HTTP pour supprimer le cookie
     * @return un {@link LogoutResponse} vide confirmant la déconnexion
     */
    @Transactional
    public LogoutResponse logout(HttpServletRequest httpRequest, HttpServletResponse response) {
        String refreshToken = getRefreshToken(httpRequest);

        if (refreshToken != null && !refreshToken.isBlank()) {
            tokenService.revokeRefreshToken(refreshToken);
        }
        ResponseCookie deleteCookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/auth/refresh")
                .maxAge(0)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, deleteCookie.toString());

        return new LogoutResponse();
    }

    /**
     * Rafraîchit la paire de tokens via rotation du refresh token.
     *
     * <p>
     * Implémente la rotation de token (RFC 6819 §5.2.2.3) : le refresh token
     * présenté est immédiatement révoqué et un nouveau est émis. Si un token
     * révoqué
     * est réutilisé, cela indique un vol de token et toute la famille de tokens est
     * révoquée (détection de réutilisation).
     *
     * @param httpRequest la requête HTTP contenant le cookie refreshToken
     * @param response    la réponse HTTP pour y déposer le nouveau cookie
     * @return un {@link TokenResponse} avec un nouvel access token et refresh token
     * @throws ApiException {@code 401 UNAUTHORIZED} si le refresh token est absent,
     *                      expiré ou révoqué
     */
    @Transactional
    public TokenResponse refresh(HttpServletRequest httpRequest, HttpServletResponse response) {
        String refreshToken = getRefreshToken(httpRequest);

        if (refreshToken == null || refreshToken.isBlank()) {
            throw new ApiException("REFRESH_TOKEN_MISSING", HttpStatus.UNAUTHORIZED);
        }

        return tokenService.rotateRefreshToken(refreshToken, httpRequest, response);
    }

    /**
     * Supprime le compte de l'utilisateur en l'anonymisant (conformité RGPD).
     *
     * <p>
     * Le compte n'est pas physiquement supprimé mais anonymisé : username, email
     * et mot de passe sont remplacés par des valeurs aléatoires. Tous les tokens
     * actifs sont révoqués avant l'anonymisation.
     *
     * @param httpRequest la requête HTTP contenant le cookie refreshToken
     * @param response    la réponse HTTP pour supprimer le cookie
     * @return un {@link DeleteResponse} confirmant la suppression
     * @throws ApiException {@code 401 UNAUTHORIZED} si le refresh token est absent
     *                      ou invalide
     * @throws ApiException {@code 404 NOT_FOUND} si l'utilisateur n'existe pas
     */
    @Transactional
    public DeleteResponse delete(HttpServletRequest httpRequest, HttpServletResponse response) {
        String refreshToken = getRefreshToken(httpRequest);
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new ApiException("REFRESH_TOKEN_MISSING", HttpStatus.UNAUTHORIZED);
        }

        TokenValidation validation = tokenService.validateRefreshToken(refreshToken);
        long userId = validation.userId();

        UserEntity userEntity = userRepository.findById(userId)
                .orElseThrow(() -> new ApiException("USER_NOT_FOUND", HttpStatus.NOT_FOUND));

        tokenService.revokeAllTokensForUser(userEntity.getId());

        String anonymousUsername = UserDataGenerator.generateRandomUsername();
        String anonymousEmail = UserDataGenerator.generateRandomEmail();
        String randomHash = passwordEncoder.encode(UserDataGenerator.generateRandomPassword());

        userRepository.anonymizeUser(userEntity.getId(), anonymousUsername, anonymousEmail, randomHash, Instant.now());

        ResponseCookie deleteCookie = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(true)
                .sameSite("Strict")
                .path("/auth/refresh")
                .maxAge(0)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, deleteCookie.toString());

        log.info("User delete: id={}", userEntity.getId());

        return new DeleteResponse();
    }

    /**
     * Extrait le refresh token du cookie HTTP de la requête.
     *
     * @param httpRequest la requête HTTP
     * @return la valeur du cookie {@code refreshToken}, ou {@code null} si absent
     */
    public String getRefreshToken(HttpServletRequest httpRequest) {
        String refreshToken = null;

        Cookie[] cookies = httpRequest.getCookies();
        if (cookies != null) {
            for (Cookie c : cookies) {
                if ("refreshToken".equals(c.getName())) {
                    refreshToken = c.getValue();
                    break;
                }
            }
        }

        return refreshToken;
    }

    /**
     * Retourne le profil de l'utilisateur authentifié à partir de son access token.
     *
     * <p>
     * Valide le JWT dans le header {@code Authorization: Bearer <token>}, extrait
     * le {@code userId} du claim {@code sub}, puis charge l'entité utilisateur.
     *
     * @param request la requête HTTP contenant le header Authorization
     * @return le profil de l'utilisateur ({@link UserProfileResponse})
     * @throws ApiException {@code 401 UNAUTHORIZED} si le token est absent,
     *                      invalide ou expiré
     * @throws ApiException {@code 403 FORBIDDEN} si le compte est désactivé ou
     *                      banni
     * @throws ApiException {@code 404 NOT_FOUND} si l'utilisateur n'existe plus
     */
    public UserProfileResponse getCurrentUser(HttpServletRequest request) {
        String authHeader = request.getHeader(org.springframework.http.HttpHeaders.AUTHORIZATION);
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new fr.synqkro.api.common.exception.ApiException("ACCESS_TOKEN_MISSING",
                    org.springframework.http.HttpStatus.UNAUTHORIZED);
        }

        String token = authHeader.substring(7).trim();
        if (!jwtTokenProvider.validateToken(token)) {
            throw new fr.synqkro.api.common.exception.ApiException("ACCESS_TOKEN_INVALID",
                    org.springframework.http.HttpStatus.UNAUTHORIZED);
        }

        io.jsonwebtoken.Claims claims = jwtTokenProvider.parseToken(token);
        long userId;
        try {
            userId = Long.parseLong(claims.getSubject());
        } catch (Exception ex) {
            throw new fr.synqkro.api.common.exception.ApiException("ACCESS_TOKEN_INVALID",
                    org.springframework.http.HttpStatus.UNAUTHORIZED);
        }

        fr.synqkro.api.common.entity.UserEntity user = userRepository.findById(userId)
                .orElseThrow(() -> new fr.synqkro.api.common.exception.ApiException("USER_NOT_FOUND",
                        org.springframework.http.HttpStatus.NOT_FOUND));

        if (user.getStatus() != fr.synqkro.api.common.enums.UserStatus.ACTIVE) {
            throw new fr.synqkro.api.common.exception.ApiException("USER_FORBIDDEN",
                    org.springframework.http.HttpStatus.FORBIDDEN);
        }

        return new UserProfileResponse(
                String.valueOf(user.getId()),
                user.getUsername(),
                user.getEmail(),
                user.getAvatarKey(),
                user.isEmailVerified(),
                user.getCreatedAt().toString());
    }

    /**
     * Génère un token de vérification email sécurisé.
     * Utilise {@link SecureRandom} pour garantir l'imprévisibilité.
     *
     * @return token URL-safe Base64 de 43 caractères (32 bytes)
     */
    private String generateEmailVerifyToken() {
        byte[] bytes = new byte[EMAIL_VERIFY_TOKEN_BYTES];
        new SecureRandom().nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

}