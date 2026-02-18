package fr.synqkro.api.common.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import fr.synqkro.api.common.dto.ErrorDto;

import java.util.Collections;
import java.util.List;

/**
 * Wrapper standard pour toutes les réponses API.
 * Format uniforme: {success: true, data: {...}} ou {success: false, error:
 * {...}}
 * Les champs null sont exclus du JSON.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiResponse<T>(
        boolean success,
        T data,
        List<ErrorDto> error) {
    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(true, data, null);
    }

    public static <T> ApiResponse<T> failure(String code, String message) {
        return new ApiResponse<>(false, null, Collections.singletonList(new ErrorDto(code, message)));
    }

    public static <T> ApiResponse<T> failure(ErrorDto errorDto) {
        return new ApiResponse<>(false, null, Collections.singletonList(errorDto));
    }

    public static <T> ApiResponse<T> failure(List<ErrorDto> errorDto) {
        return new ApiResponse<>(false, null, errorDto);
    }
}