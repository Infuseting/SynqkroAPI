package fr.synqkro.api.common.exception;

import org.springframework.http.HttpStatus;

public class ApiException extends RuntimeException {

    private final String     code;
    private final HttpStatus status;

    public ApiException(String code, HttpStatus status) {
        super(code);
        this.code   = code;
        this.status = status;
    }

    public ApiException(String code, HttpStatus status, Throwable cause) {
        super(code, cause);
        this.code   = code;
        this.status = status;
    }

    public String getCode() {
        return code;
    }

    public HttpStatus getStatus() {
        return status;
    }
}