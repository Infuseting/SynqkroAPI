package fr.synqkro.api.common.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

import java.util.HashMap;
import java.util.Map;

/**
 * Configuration des propriétés de sécurité depuis application.yaml.
 */
@Configuration
@ConfigurationProperties(prefix = "security")
@Data
public class SecurityProperties {

    private String encryptionKey;
    private JwtProperties jwt = new JwtProperties();
    private RateLimitProperties rateLimit = new RateLimitProperties();
    private HeadersProperties headers = new HeadersProperties();

    @Data
    public static class JwtProperties {
        private String secret;
        private long accessTokenExpiry = 900; // 15 min
        private long refreshTokenExpiry = 2592000; // 30 jours
    }

    @Data
    public static class RateLimitProperties {
        private boolean enabled = true;
        private Map<String, Integer> routes = new HashMap<>();
    }

    @Data
    public static class HeadersProperties {
        private CorsProperties cors = new CorsProperties();
        private CspProperties csp = new CspProperties();
        private HstsProperties hsts = new HstsProperties();
        private String xFrameOptions = "DENY";
        private String xContentTypeOptions = "nosniff";
        private String xXssProtection = "1; mode=block";
        private String referrerPolicy = "no-referrer-when-downgrade";
    }

    @Data
    public static class CorsProperties {
        private boolean enabled = true;
        private String allowedOrigins = "http://localhost:3000";
        private String allowedMethods = "GET,POST,PUT,DELETE,PATCH,OPTIONS";
        private String allowedHeaders = "*";
        private String exposedHeaders = "Authorization,Content-Type";
        private boolean allowCredentials = true;
        private long maxAge = 3600;
    }

    @Data
    public static class CspProperties {
        private boolean enabled = true;
        private String policy = "default-src 'self'";
    }

    @Data
    public static class HstsProperties {
        private boolean enabled = true;
        private long maxAge = 31536000;
        private boolean includeSubdomains = true;
        private boolean preload = true;
    }
}
