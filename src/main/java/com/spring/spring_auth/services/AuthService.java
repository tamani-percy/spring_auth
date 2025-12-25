package com.spring.spring_auth.services;

import com.spring.spring_auth.configs.security.ContextUtil;
import com.spring.spring_auth.configs.security.jwt.JwtAuthenticationProvider;
import com.spring.spring_auth.configs.security.services.UserDetailsImpl;
import com.spring.spring_auth.dtos.requests.LoginRequest;
import com.spring.spring_auth.dtos.requests.SignupRequest;
import com.spring.spring_auth.dtos.responses.LoginResponse;
import com.spring.spring_auth.models.*;
import com.spring.spring_auth.repositories.ProviderRepository;
import com.spring.spring_auth.repositories.RefreshTokenRepository;
import com.spring.spring_auth.repositories.RoleRepository;
import com.spring.spring_auth.repositories.UserRepository;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.LocalDateTime;
import java.util.UUID;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;
    private final PasswordEncoder passwordEncoder;
    private final ProviderRepository providerRepository;
    private final ContextUtil contextUtil;
    private final RefreshTokenRepository refreshTokenRepository;

    public AuthService(UserRepository userRepository, RoleRepository roleRepository, JwtAuthenticationProvider jwtAuthenticationProvider, PasswordEncoder passwordEncoder, ProviderRepository providerRepository, ContextUtil contextUtil, RefreshTokenRepository refreshTokenRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.jwtAuthenticationProvider = jwtAuthenticationProvider;
        this.passwordEncoder = passwordEncoder;
        this.providerRepository = providerRepository;
        this.contextUtil = contextUtil;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public String createAdmin(SignupRequest signupRequest) {
        if (userRepository.findByUsername(signupRequest.getUsername()).isEmpty()) {

            User user = new User();
            user.setUsername(signupRequest.getUsername());
            user.setPassword(passwordEncoder.encode(signupRequest.getPassword()));
            Provider provider = providerRepository.findByProvider(EProvider.USERNAMEANDPASSWORD).orElseThrow(() -> new RuntimeException("Provider not found"));
            Role role = roleRepository.findByRole(ERole.ROLE_ADMIN)
                    .orElseThrow(() -> new RuntimeException("Admin role not found"));

            user.setRole(role);
            user.setProvider(provider);
            userRepository.save(user);

            return "Admin registered successfully!";
        }
        return "Unable to create the administrator. Please check your details and try again.";
    }

    public void saveAuthorizationCode(String authorizationCode, Long userId) {
        if (userRepository.findById(userId).isPresent()) {
            User user = userRepository.findById(userId).get();
            user.setAuthorizationCode(authorizationCode);
            userRepository.save(user);
        } else {
            throw new RuntimeException("User not found");
        }
    }


    public String signup(SignupRequest signupRequest) {
        if (userRepository.findByUsername(signupRequest.getUsername()).isEmpty()) {
            User user = new User();
            user.setUsername(signupRequest.getUsername());
            user.setPassword(passwordEncoder.encode(signupRequest.getPassword()));
            Provider provider = providerRepository.findByProvider(EProvider.USERNAMEANDPASSWORD).orElseThrow(() -> new RuntimeException("Provider not found"));
            Role role = roleRepository.findByRole(ERole.ROLE_USER)
                    .orElseThrow(() -> new RuntimeException("User role not found"));
            user.setRole(role);
            user.setProvider(provider);
            userRepository.save(user);
            return "User registered successfully!";
        }
        return "Unable to create the user. Please check your details and try again.";
    }

    public ResponseEntity<LoginResponse> login(LoginRequest loginRequest, HttpServletResponse httpServletResponse) {

        // Validate input
        if (loginRequest == null ||
                loginRequest.getUsername() == null || loginRequest.getUsername().isBlank() ||
                loginRequest.getPassword() == null || loginRequest.getPassword().isBlank()) {

            throw new RuntimeException("Username and password must be provided.");
        }

        // Find user
        User user = userRepository.findByUsername(loginRequest.getUsername())
                .orElse(null);

        String ctx = contextUtil.generateContext();
        String ctxHash = contextUtil.hashContext(ctx);

        if (user == null) {
            throw new RuntimeException("Invalid username or password.");
        }

        // Verify password (compare raw vs encoded)
        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            throw new RuntimeException("Invalid username or password.");
        }

        // Build authentication context
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication);

            // Generate JWT
            String jwtToken = jwtAuthenticationProvider.generateJwtToken(authentication, ctxHash);


            RefreshToken refreshToken = new RefreshToken();
            refreshToken.setUser(user);
            refreshToken.setToken(UUID.randomUUID().toString());
            refreshToken.setExpiryDate(
                    LocalDateTime.now().plusDays(30)
            );
            refreshTokenRepository.save(refreshToken);

            ResponseCookie ctxCookie = ResponseCookie
                    .from("__Host-ctx", ctx)
                    .httpOnly(true)
                    .secure(true)
                    .sameSite("None")
                    .path("/")
                    .maxAge(Duration.ofMinutes(15))
                    .build();

            ResponseCookie refreshCookie = ResponseCookie
                    .from("__Host-refresh", refreshToken.getToken())
                    .httpOnly(true)
                    .secure(true)
                    .sameSite("None")
                    .path("/")
                    .maxAge(Duration.ofDays(30))
                    .build();

        httpServletResponse.addHeader(HttpHeaders.SET_COOKIE, ctxCookie.toString());
        httpServletResponse.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());

        // Return success response
        return ResponseEntity.ok().body(
                new LoginResponse(
                        user.getUsername(),
                        jwtToken
                )
        );

    }
}
