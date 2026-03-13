package com.shop.apigatewayservice.filters;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import com.shop.apigatewayservice.exception.JwtAuthenticationException;
import com.shop.apigatewayservice.util.JwtUtil;
import org.springframework.beans.factory.annotation.Value;
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
import java.util.Objects;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class JwtTokenFilter implements GlobalFilter, Ordered {

    private final JwtUtil jwtUtil;

    @Value("${internal.internal-secret}")
    private String internalSecret;

    private static final Set<String> PUBLIC_AUTH_PATHS = Set.of(
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/refresh",
            "/api/auth/validate"
    );

    private static final Set<String> SWAGGER_PATHS = Set.of(
            "/v3/api-docs",
            "/swagger-ui",
            "/swagger"
    );

    private static final Set<String> ACTUATOR_PATHS = Set.of(
            "/actuator/health",
            "/actuator/info",
            "/actuator/metrics",
            "/actuator/prometheus"
    );

    @Override
    public int getOrder() {
        return -1;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {

        String path = exchange.getRequest().getPath().value();

        if (isPathExcluded(path, PUBLIC_AUTH_PATHS) ||
                isPathExcluded(path, SWAGGER_PATHS) ||
                isPathExcluded(path, ACTUATOR_PATHS)) {

            if (isPathExcluded(path, SWAGGER_PATHS)) {
                ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                        .header("X-Internal-Auth", internalSecret)
                        .build();
                return chain.filter(exchange.mutate().request(mutatedRequest).build());
            }
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
        Object userIdObj = claims.get("userId");

        if (userIdObj == null) {
            throw new JwtAuthenticationException("Missing userId claim");
        }

        String userId = userIdObj.toString();

        String subject = claims.getSubject();
        if (subject == null) {
            throw new JwtAuthenticationException("Missing subject claim");
        }

        Object rolesObj = claims.get("roles");
        List<String> roles;

        if (rolesObj instanceof List<?> list) {
            roles = list.stream()
                    .filter(Objects::nonNull)
                    .map(Object::toString)
                    .toList();
        }
        else {
            roles = List.of();
        }

        ServerHttpRequest mutatedRequest = exchange.getRequest().mutate()
                .headers(h -> {
                    h.remove(HttpHeaders.AUTHORIZATION);
                    h.remove("X-User-Id");
                    h.remove("X-Username");
                    h.remove("X-Roles");
                    h.add("X-User-Id", userId);
                    h.add("X-Username", subject);
                    h.add("X-Roles", String.join(",", roles));
                    h.add("X-Internal-Auth", internalSecret);
                })
                .build();

        return exchange.mutate().request(mutatedRequest).build();
    }

    private boolean isPathExcluded(String path, Set<String> prefixes){
        return prefixes.stream().anyMatch(path::startsWith);
    }

}
