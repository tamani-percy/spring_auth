package com.spring.spring_auth.services;

import com.spring.spring_auth.models.RefreshToken;
import com.spring.spring_auth.models.User;
import com.spring.spring_auth.repositories.RefreshTokenRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private final RefreshTokenRepository refreshTokenRepository;

    @Value("${jwt_refresh_expiration}")
    private long refreshExpirationMs;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository) {
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public RefreshToken create(User user) {
        RefreshToken rt = new RefreshToken();
        rt.setUser(user);
        rt.setToken(UUID.randomUUID().toString());
        rt.setExpiryDate(
                LocalDateTime.now().plus(Duration.ofMillis(refreshExpirationMs))
        );
        return refreshTokenRepository.save(rt);
    }

    public RefreshToken verify(String token) {
        RefreshToken rt = refreshTokenRepository.findByToken(token)
                .orElseThrow(() -> new RuntimeException("Invalid refresh"));

        if (rt.getExpiryDate().isBefore(LocalDateTime.now())) {
            refreshTokenRepository.delete(rt);
            throw new RuntimeException("Refresh expired");
        }
        return rt;
    }

    public void rotate(RefreshToken oldToken) {
        refreshTokenRepository.delete(oldToken);
    }
}
