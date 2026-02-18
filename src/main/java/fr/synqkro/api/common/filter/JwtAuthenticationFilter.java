package fr.synqkro.api.common.filter;

import fr.synqkro.api.common.provider.JwtTokenProvider;
import fr.synqkro.api.common.repository.RefreshTokenRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

/**
 * Filtre JWT pour authentifier les requêtes via Access Token.
 * S'exécute en 2ème position après RateLimitFilter.
 */
@Component
@Order(2)
@RequiredArgsConstructor
@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final RefreshTokenRepository refreshTokenRepository;

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        // Extraire le token Bearer
        String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        String jwt = authHeader.substring(7);

        try {
            // Valider et extraire claims
            if (jwtTokenProvider.validateToken(jwt)) {
                Long userId = Long.valueOf(jwtTokenProvider.parseToken(jwt).getSubject());

                // Créer authentication
                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                        userId.toString(),
                        null,
                        Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")));

                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                // Mettre dans le context Spring Security
                SecurityContextHolder.getContext().setAuthentication(authentication);

                log.debug("JWT authentication successful for user {}", userId);
            } else {
                log.warn("Invalid JWT token");
            }

        } catch (Exception e) {
            log.error("JWT authentication failed", e);
            // Ne pas bloquer la requête, laisser les autres filtres gérer
        }

        filterChain.doFilter(request, response);
    }
}
