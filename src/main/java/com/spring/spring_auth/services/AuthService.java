package com.spring.spring_auth.services;

import com.spring.spring_auth.configs.jwt.JwtAuthenticationProvider;
import com.spring.spring_auth.configs.security.services.UserDetailsImpl;
import com.spring.spring_auth.dtos.requests.LoginRequest;
import com.spring.spring_auth.dtos.requests.SignupRequest;
import com.spring.spring_auth.dtos.responses.LoginResponse;
import com.spring.spring_auth.dtos.responses.LogoutResponse;
import com.spring.spring_auth.models.*;
import com.spring.spring_auth.repositories.ProviderRepository;
import com.spring.spring_auth.repositories.RoleRepository;
import com.spring.spring_auth.repositories.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;
    private final PasswordEncoder passwordEncoder;
    private final ProviderRepository providerRepository;

    public AuthService(UserRepository userRepository, RoleRepository roleRepository, JwtAuthenticationProvider jwtAuthenticationProvider, PasswordEncoder passwordEncoder, ProviderRepository providerRepository) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.jwtAuthenticationProvider = jwtAuthenticationProvider;
        this.passwordEncoder = passwordEncoder;
        this.providerRepository = providerRepository;
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

    public ResponseEntity<?> login(LoginRequest loginRequest) {

        // Validate input
        if (loginRequest == null ||
                loginRequest.getUsername() == null || loginRequest.getUsername().isBlank() ||
                loginRequest.getPassword() == null || loginRequest.getPassword().isBlank()) {

            return ResponseEntity
                    .badRequest()
                    .body("Username and password must be provided.");
        }

        // Find user
        User user = userRepository.findByUsername(loginRequest.getUsername())
                .orElse(null);

        if (user == null) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid username or password.");
        }

        // Verify password (compare raw vs encoded)
        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPassword())) {
            return ResponseEntity
                    .status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid username or password.");
        }

        // Build authentication context
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        UsernamePasswordAuthenticationToken authentication =
                new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication);

        // Generate JWT
        ResponseCookie jwtToken = jwtAuthenticationProvider.generateJwtCookie(user);

        // Return success response
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtToken.toString())
                .body(new LoginResponse(userDetails.getUsername()));

    }

    public ResponseEntity<?> logout() {
        ResponseCookie jwtToken = jwtAuthenticationProvider.getCleanJwtCookie();
        return ResponseEntity.ok().header(HttpHeaders.SET_COOKIE, jwtToken.toString())
                .body(new LogoutResponse("You've been signed out!"));
    }

    public ResponseEntity<Boolean> verifyToken(HttpServletRequest httpServletRequest) {
        String token = jwtAuthenticationProvider.getTokenFromCookie(httpServletRequest);
        if (token != null && jwtAuthenticationProvider.validateToken(token)) {
            return ResponseEntity.ok().body(true);
        } else {
            return ResponseEntity.ok().body(false);
        }
    }
}
