package fr.synqkro.api.common.handler;

import fr.synqkro.api.common.constants.ErrorCodes;
import fr.synqkro.api.common.dto.ErrorDto;
import fr.synqkro.api.common.dto.response.ApiResponse;
import fr.synqkro.api.common.exception.ApiException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.MethodArgumentTypeMismatchException;

import java.util.HashMap;
import java.util.Map;

/**
 * Gestionnaire global des exceptions pour l'API.
 * Convertit toutes les exceptions en réponse ApiResponse uniforme avec
 * {success: false, error: {...}}.
 */
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

        /**
         * Gère les exceptions métier (ApiException).
         */
        @ExceptionHandler(ApiException.class)
        public ResponseEntity<ApiResponse<Void>> handleApiException(ApiException ex, HttpServletRequest request) {
                log.warn("API Exception: {} - {}", ex.getCode(), ex.getMessage());

                ErrorDto error = new ErrorDto(
                                ex.getCode(),
                                ex.getMessage(),
                                request.getRequestURI());

                return ResponseEntity.status(ex.getStatus())
                                .body(ApiResponse.failure(error));
        }

        /**
         * Gère les erreurs de validation Jakarta (@Valid).
         */
        @ExceptionHandler(MethodArgumentNotValidException.class)
        public ResponseEntity<ApiResponse<Void>> handleValidationException(
                        MethodArgumentNotValidException ex, HttpServletRequest request) {

                Map<String, String> validationErrors = new HashMap<>();
                ex.getBindingResult().getAllErrors().forEach(error -> {
                        String fieldName = ((FieldError) error).getField();
                        String errorMessage = error.getDefaultMessage();
                        validationErrors.put(fieldName, errorMessage);
                });

                log.warn("Validation error: {}", validationErrors);

                ErrorDto error = ErrorDto.builder()
                                .code(ErrorCodes.VALIDATION_ERROR)
                                .message("Erreur de validation des données")
                                .path(request.getRequestURI())
                                .details(validationErrors)
                                .build();

                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(ApiResponse.failure(error));
        }

        /**
         * Gère les erreurs de contraintes de validation.
         */
        @ExceptionHandler(ConstraintViolationException.class)
        public ResponseEntity<ApiResponse<Void>> handleConstraintViolation(
                        ConstraintViolationException ex, HttpServletRequest request) {

                Map<String, String> validationErrors = new HashMap<>();
                ex.getConstraintViolations().forEach(violation -> {
                        String fieldName = violation.getPropertyPath().toString();
                        String errorMessage = violation.getMessage();
                        validationErrors.put(fieldName, errorMessage);
                });

                log.warn("Constraint violation: {}", validationErrors);

                ErrorDto error = ErrorDto.builder()
                                .code(ErrorCodes.VALIDATION_ERROR)
                                .message("Erreur de validation des contraintes")
                                .path(request.getRequestURI())
                                .details(validationErrors)
                                .build();

                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(ApiResponse.failure(error));
        }

        /**
         * Gère les erreurs d'authentification Spring Security.
         */
        @ExceptionHandler(AuthenticationException.class)
        public ResponseEntity<ApiResponse<Void>> handleAuthenticationException(
                        AuthenticationException ex, HttpServletRequest request) {

                log.warn("Authentication error: {}", ex.getMessage());

                ErrorDto error = new ErrorDto(
                                ErrorCodes.UNAUTHORIZED,
                                "Authentification requise",
                                request.getRequestURI());

                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                .body(ApiResponse.failure(error));
        }

        /**
         * Gère les erreurs de mauvaises credentials.
         */
        @ExceptionHandler(BadCredentialsException.class)
        public ResponseEntity<ApiResponse<Void>> handleBadCredentials(
                        BadCredentialsException ex, HttpServletRequest request) {

                log.warn("Bad credentials: {}", ex.getMessage());

                ErrorDto error = new ErrorDto(
                                ErrorCodes.INVALID_CREDENTIALS,
                                "Identifiants invalides",
                                request.getRequestURI());

                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                                .body(ApiResponse.failure(error));
        }

        /**
         * Gère les erreurs d'accès refusé (403 Forbidden).
         */
        @ExceptionHandler(AccessDeniedException.class)
        public ResponseEntity<ApiResponse<Void>> handleAccessDenied(
                        AccessDeniedException ex, HttpServletRequest request) {

                log.warn("Access denied: {}", ex.getMessage());

                ErrorDto error = new ErrorDto(
                                ErrorCodes.FORBIDDEN,
                                "Accès refusé",
                                request.getRequestURI());

                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                                .body(ApiResponse.failure(error));
        }

        /**
         * Gère les erreurs de type d'argument invalide.
         */
        @ExceptionHandler(MethodArgumentTypeMismatchException.class)
        public ResponseEntity<ApiResponse<Void>> handleTypeMismatch(
                        MethodArgumentTypeMismatchException ex, HttpServletRequest request) {

                log.warn("Type mismatch: {} for parameter {}", ex.getValue(), ex.getName());

                ErrorDto error = new ErrorDto(
                                ErrorCodes.INVALID_INPUT,
                                String.format("Type invalide pour le paramètre '%s'", ex.getName()),
                                request.getRequestURI());

                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(ApiResponse.failure(error));
        }

        /**
         * Gère les IllegalArgumentException.
         */
        @ExceptionHandler(IllegalArgumentException.class)
        public ResponseEntity<ApiResponse<Void>> handleIllegalArgument(
                        IllegalArgumentException ex, HttpServletRequest request) {

                log.warn("Illegal argument: {}", ex.getMessage());

                ErrorDto error = new ErrorDto(
                                ErrorCodes.BAD_REQUEST,
                                ex.getMessage(),
                                request.getRequestURI());

                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                                .body(ApiResponse.failure(error));
        }

        /**
         * Gère toutes les autres exceptions non gérées.
         */
        @ExceptionHandler(Exception.class)
        public ResponseEntity<ApiResponse<Void>> handleGenericException(
                        Exception ex, HttpServletRequest request) {

                log.error("Unhandled exception: ", ex);

                ErrorDto error = new ErrorDto(
                                ErrorCodes.INTERNAL_SERVER_ERROR,
                                "Une erreur interne s'est produite",
                                request.getRequestURI());

                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                                .body(ApiResponse.failure(error));
        }
}
