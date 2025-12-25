package com.spring.spring_auth.configs.security.jwt;

import com.spring.spring_auth.configs.security.services.UserDetailsImpl;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;

@Component
@Slf4j
public class JwtAuthenticationProvider {

    @Value("${jwt_secret}")
    private String jwtSecret;

    @Value("${jwt_expiration}")
    private long jwtExpiration;

    private SecretKey key;

    @PostConstruct
    protected void init() {
        this.key = Keys.hmacShaKeyFor(
                Decoders.BASE64.decode(jwtSecret)
        );
    }

    public String generateJwtToken(
            Authentication authentication,
            String ctxHash
    ) {
        UserDetailsImpl principal =
                (UserDetailsImpl) authentication.getPrincipal();

        return Jwts.builder()
                .subject(principal.getEmail())
                .claim("ctx_hash", ctxHash)
                .issuedAt(new Date())
                .expiration(
                        new Date((new Date()).getTime() + jwtExpiration)
                )
                .signWith(key)
                .compact();
    }

    public Claims validateAndParse(String token) {
        try {
            return Jwts.parser()
                    .verifyWith(key)
                    .build()
                    .parseSignedClaims(token).getPayload();
        } catch (JwtException e) {
            log.warn("Invalid JWT: {}", e.getMessage());
            throw e;
        }
    }

    public boolean validateToken(String token) {
        try {
            validateAndParse(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    public String getUsernameFromToken(String token) {
        return validateAndParse(token).getSubject();
    }
}

