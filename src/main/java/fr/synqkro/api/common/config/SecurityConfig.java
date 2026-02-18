package fr.synqkro.api.common.config;

import fr.synqkro.api.common.filter.JwtAuthenticationFilter;
import fr.synqkro.api.common.filter.RateLimitFilter;
import fr.synqkro.api.common.filter.SessionCoherenceFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

        private final RateLimitFilter rateLimitFilter;
        private final JwtAuthenticationFilter jwtAuthenticationFilter;
        private final SessionCoherenceFilter sessionCoherenceFilter;

        @Bean
        public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
                http
                                // Désactiver CSRF (API REST stateless)
                                .csrf(csrf -> csrf.disable())

                                // Configuration CORS
                                .cors(cors -> cors.configurationSource(corsConfigurationSource()))

                                // Stateless sessions (JWT)
                                .sessionManagement(session -> session
                                                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                                // Routes publiques vs protégées
                                .authorizeHttpRequests(auth -> auth
                                                // Routes publiques
                                                .requestMatchers(
                                                                "/auth/login",
                                                                "/auth/register",
                                                                "/auth/refresh",
                                                                "/auth/email/confirm",
                                                                "/auth/password/forgot",
                                                                "/auth/password/reset",
                                                                "/actuator/health",
                                                                "/v3/api-docs/**",
                                                                "/swagger-ui/**")
                                                .permitAll()

                                                // Toutes les autres routes nécessitent une authentification
                                                .anyRequest().authenticated())

                                // Ajouter les filtres personnalisés dans l'ordre
                                .addFilterBefore(rateLimitFilter, UsernamePasswordAuthenticationFilter.class)
                                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
                                .addFilterBefore(sessionCoherenceFilter, UsernamePasswordAuthenticationFilter.class)

                                // Désactiver form login et http basic
                                .formLogin(form -> form.disable())
                                .httpBasic(basic -> basic.disable())

                                // Headers de sécurité
                                .headers(headers -> headers
                                                .contentSecurityPolicy(csp -> csp
                                                                .policyDirectives(
                                                                                "default-src 'self'; frame-ancestors 'none';"))
                                                .frameOptions(frame -> frame.deny()));

                return http.build();
        }

        @Bean
        public CorsConfigurationSource corsConfigurationSource() {
                CorsConfiguration configuration = new CorsConfiguration();

                // Origines autorisées (à configurer selon environnement)
                configuration.setAllowedOrigins(Arrays.asList(
                                "http://localhost:3000",
                                "http://localhost:5173",
                                "https://app.synqkro.fr"));

                // Méthodes autorisées
                configuration.setAllowedMethods(Arrays.asList(
                                "GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));

                // Headers autorisés
                configuration.setAllowedHeaders(Arrays.asList(
                                "Authorization",
                                "Content-Type",
                                "X-Requested-With",
                                "X-Fingerprint",
                                "X-Device-Name"));

                // Headers exposés au client
                configuration.setExposedHeaders(Arrays.asList(
                                "X-RateLimit-Remaining",
                                "X-RateLimit-Retry-After",
                                "X-Session-Risk-Score"));

                // Credentials autorisés (cookies, headers auth)
                configuration.setAllowCredentials(true);

                // Durée cache preflight
                configuration.setMaxAge(3600L);

                UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
                source.registerCorsConfiguration("/**", configuration);
                return source;
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
                return Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8();
        }
}
