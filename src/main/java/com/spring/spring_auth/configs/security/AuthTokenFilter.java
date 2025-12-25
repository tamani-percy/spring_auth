package com.spring.spring_auth.configs.security;

import com.spring.spring_auth.configs.security.jwt.JwtAuthenticationProvider;
import com.spring.spring_auth.configs.security.services.UserDetailsServiceImpl;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

@Component
public class AuthTokenFilter extends OncePerRequestFilter {

    private final JwtAuthenticationProvider jwtProvider;
    private final UserDetailsServiceImpl userDetailsService;
    private final ContextUtil contextUtil;

    public AuthTokenFilter(
            JwtAuthenticationProvider jwtProvider,
            UserDetailsServiceImpl userDetailsService, ContextUtil contextUtil
    ) {
        this.jwtProvider = jwtProvider;
        this.userDetailsService = userDetailsService;
        this.contextUtil = contextUtil;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        String uri = request.getRequestURI();
        Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

        String jwt = parseJwt(request);

        // No JWT? Not our problem. Continue.
        if (jwt == null) {
            logger.debug("No JWT found in request to: {}", uri);
            filterChain.doFilter(request, response);
            return;
        }

        try {
            // Extract ctx cookie
            String ctx = extractCtxCookie(request);
            if (ctx == null) {
                logger.warn("JWT present but __Host-ctx cookie missing for: {}", uri);
                SecurityContextHolder.clearContext();
                filterChain.doFilter(request, response);
                return;
            }

            // Validate JWT + ctx
            var claims = jwtProvider.validateAndParse(jwt);

            String expectedCtxHash = claims.get("ctx_hash", String.class);
            String actualCtxHash = contextUtil.hashContext(ctx);

            if (!MessageDigest.isEqual(
                    expectedCtxHash.getBytes(StandardCharsets.UTF_8),
                    actualCtxHash.getBytes(StandardCharsets.UTF_8))) {
                logger.warn("ctx_hash mismatch for user: {}", claims.getSubject());
                SecurityContextHolder.clearContext();
                filterChain.doFilter(request, response);
                return;
            }

            // Authenticate user
            String username = claims.getSubject();
            UserDetails userDetails =
                    userDetailsService.loadUserByUsername(username);

            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                            userDetails, null, userDetails.getAuthorities()
                    );

            authentication.setDetails(
                    new WebAuthenticationDetailsSource()
                            .buildDetails(request)
            );

            SecurityContextHolder.getContext()
                    .setAuthentication(authentication);

        } catch (Exception e) {
            logger.error("Authentication error: {}", e.getMessage());
            SecurityContextHolder.clearContext();
        }

        filterChain.doFilter(request, response);
    }

    private String parseJwt(HttpServletRequest request) {
        String header = request.getHeader("Authorization");
        if (StringUtils.hasText(header) && header.startsWith("Bearer ")) {
            return header.substring(7);
        }
        return null;
    }

    private String extractCtxCookie(HttpServletRequest request) {
        if (request.getCookies() == null) return null;
        for (var cookie : request.getCookies()) {
            if ("__Host-ctx".equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }
}
