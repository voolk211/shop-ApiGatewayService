package org.example.apigatewayservice.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.example.apigatewayservice.exception.JwtAuthenticationException;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtTokenFilter implements GlobalFilter, Ordered {

    private final JwtUtil jwtUtil;

    @Override
    public int getOrder() {
        return -1;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        String path = exchange.getRequest().getPath().value();

        if (path.startsWith("/api/auth/")) {
            return chain.filter(exchange);
        }

        String authHeaders = exchange.getRequest()
                .getHeaders()
                .getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeaders == null || !authHeaders.trim().toLowerCase().startsWith("bearer ")) {
            return Mono.error(new JwtAuthenticationException("Missing or invalid Authorization header"));
        }

        String token = authHeaders.substring(7);

        return Mono.fromCallable(() -> jwtUtil.validateToken(token))
                .subscribeOn(Schedulers.boundedElastic())
                .map(claims -> mutateRequest(exchange, claims))
                .flatMap(chain::filter)
                .onErrorMap(JwtException.class,
                        ex -> new JwtAuthenticationException(ex.getMessage()));

    }

    private ServerWebExchange mutateRequest(ServerWebExchange exchange, Claims claims) {
        Object userId = claims.get("userId");

        if (userId == null) {
            throw new JwtAuthenticationException("Missing userId claim");
        }

        String subject = claims.getSubject();

        if (subject == null) {
            throw new JwtAuthenticationException("Missing subject claim");
        }

        Object rolesObj = claims.get("roles");
        List<String> roles;

        if (rolesObj instanceof List<?> list) {
            roles = list.stream()
                    .map(Object::toString)
                    .toList();
        }
        else {
            roles = List.of();
        }

        ServerHttpRequest mutatedRequest = exchange.getRequest()
                .mutate()
                .header("X-User-Id", userId.toString())
                .header("X-Username", subject)
                .header("X-Roles", String.join(",", roles))
                .build();

        return exchange.mutate().request(mutatedRequest).build();
    }
}
