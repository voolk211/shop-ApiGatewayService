package org.example.apigatewayservice.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import lombok.RequiredArgsConstructor;
import org.example.apigatewayservice.exception.JwtAuthenticationException;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

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

        String authHeaders = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        if (authHeaders == null || !authHeaders.startsWith("Bearer ")) {
            throw new JwtAuthenticationException("Missing or invalid Authorization header");
            //exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            //return exchange.getResponse().setComplete();
        }

        String token = authHeaders.substring(7);

        try {
            Claims claims = jwtUtil.validateToken(token);

            Object userId = claims.get("userId");

            if (userId == null) {
                throw new JwtException("Missing userId");
            }

            String subject = claims.getSubject();

            if (subject == null) {
                throw new JwtException("Missing subject");
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

            return chain.filter(exchange.mutate().request(mutatedRequest).build());
        } catch (JwtException e) {
            throw new JwtAuthenticationException(e.getMessage());
        }
    }

}
