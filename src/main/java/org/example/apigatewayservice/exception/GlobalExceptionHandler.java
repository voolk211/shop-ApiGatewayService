package org.example.apigatewayservice.exception;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.boot.web.reactive.error.ErrorWebExceptionHandler;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Instant;

@Component
public class GlobalExceptionHandler implements ErrorWebExceptionHandler {

    private final ObjectMapper mapper = new ObjectMapper();

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, Throwable ex) {

        ServerHttpResponse response = exchange.getResponse();
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);

        HttpStatus status;

        if (ex instanceof JwtAuthenticationException) {
            status = HttpStatus.UNAUTHORIZED;
        }
        else {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
        }

        response.setStatusCode(status);

        ErrorResponse errorResponse = new ErrorResponse(Instant.now(),
                status.value(),
                ex.getMessage(),
                exchange.getRequest().getPath().value());

        byte[] bytes;
        try {
            bytes = mapper.writeValueAsBytes(errorResponse);
        } catch (JsonProcessingException e) {
            bytes = new byte[0];
        }

        DataBuffer buffer = response.bufferFactory().wrap(bytes);
        return response.writeWith(Mono.just(buffer));
    }
}
