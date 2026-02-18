package fr.synqkro.api.common.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filter pour ajouter les headers de sécurité à toutes les réponses HTTP.
 */
@Component
@RequiredArgsConstructor
public class SecurityHeadersFilter extends OncePerRequestFilter {

    private final SecurityProperties securityProperties;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        var headersConfig = securityProperties.getHeaders();

        // CORS Headers (si activé)
        if (headersConfig.getCors().isEnabled()) {
            var cors = headersConfig.getCors();
            response.setHeader("Access-Control-Allow-Origin", cors.getAllowedOrigins());
            response.setHeader("Access-Control-Allow-Methods", cors.getAllowedMethods());
            response.setHeader("Access-Control-Allow-Headers", cors.getAllowedHeaders());
            response.setHeader("Access-Control-Expose-Headers", cors.getExposedHeaders());
            response.setHeader("Access-Control-Allow-Credentials", String.valueOf(cors.isAllowCredentials()));
            response.setHeader("Access-Control-Max-Age", String.valueOf(cors.getMaxAge()));
        }

        // Content Security Policy
        if (headersConfig.getCsp().isEnabled()) {
            response.setHeader("Content-Security-Policy", headersConfig.getCsp().getPolicy());
        }

        // HTTP Strict Transport Security
        if (headersConfig.getHsts().isEnabled()) {
            var hsts = headersConfig.getHsts();
            String hstsValue = "max-age=" + hsts.getMaxAge();
            if (hsts.isIncludeSubdomains()) {
                hstsValue += "; includeSubDomains";
            }
            if (hsts.isPreload()) {
                hstsValue += "; preload";
            }
            response.setHeader("Strict-Transport-Security", hstsValue);
        }

        // Autres headers de sécurité
        response.setHeader("X-Frame-Options", headersConfig.getXFrameOptions());
        response.setHeader("X-Content-Type-Options", headersConfig.getXContentTypeOptions());
        response.setHeader("X-XSS-Protection", headersConfig.getXXssProtection());
        response.setHeader("Referrer-Policy", headersConfig.getReferrerPolicy());

        filterChain.doFilter(request, response);
    }
}
