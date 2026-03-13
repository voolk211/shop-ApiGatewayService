package com.shop.apigatewayservice.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;

@Component
public class JwtUtil {

    private final SecretKey secretKey;

    public JwtUtil(
            @Value("${security.jwt.secret}") String secretKey
    ) {
        this.secretKey = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }

    public Claims validateToken(String token) {
        Claims claims = parseClaims(token);
        if (!"ACCESS".equals(claims.get("tokenType"))) {
            throw new JwtException("Not an access token");
        }
        validateExpiration(claims);
        return claims;
    }

    public Claims parseClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    private void validateExpiration(Claims claims) {
        Date expiration = claims.getExpiration();

        if (expiration == null) {
            throw new JwtException("Token does not contain expiration");
        }

        if (expiration.toInstant().isBefore(Instant.now())) {
            throw new JwtException("Token expired");
        }
    }
}
