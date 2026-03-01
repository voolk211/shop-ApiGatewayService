package org.example.apigatewayservice.exception;

import java.io.Serial;

public class JwtAuthenticationException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = -5839984622772930219L;

    public JwtAuthenticationException() {
    }

    public JwtAuthenticationException(String message) {
        super(message);
    }

    public JwtAuthenticationException(Throwable cause) {
        super(cause);
    }

    public JwtAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
