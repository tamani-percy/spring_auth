package com.spring.spring_auth.configs.security.oauth;

import com.spring.spring_auth.models.ERole;
import com.spring.spring_auth.models.Provider;
import com.spring.spring_auth.models.Role;
import com.spring.spring_auth.models.User;
import com.spring.spring_auth.repositories.ProviderRepository;
import com.spring.spring_auth.repositories.RoleRepository;
import com.spring.spring_auth.repositories.UserRepository;
import com.spring.spring_auth.services.AuthService;
import com.spring.spring_auth.utilities.ProviderHelper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.UUID;

@Component
public class OAuthSuccessHandler implements AuthenticationSuccessHandler {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final ProviderRepository providerRepository;
    private final AuthService authService;

    public OAuthSuccessHandler(UserRepository userRepository, RoleRepository roleRepository, ProviderRepository providerRepository, AuthService authService) {
        this.userRepository = userRepository;
        this.roleRepository = roleRepository;
        this.providerRepository = providerRepository;
        this.authService = authService;
    }

    @Value("${frontend_url}")
    private String frontendUrl;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException {
        OAuth2AuthenticationToken authToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oauthUser = authToken.getPrincipal();
        String email = oauthUser.getAttribute("email");
        String sub = oauthUser.getAttribute("sub");
        assert sub != null;
        String provider = sub.split("\\|")[0];
        if (userRepository.findByEmail(email).isEmpty()) {
            User user = new User();
            Role role = roleRepository.findByRole(ERole.ROLE_USER).orElseThrow(() -> new RuntimeException("Role not found"));
            Provider existingProvider = providerRepository.findByProvider(ProviderHelper.getProvider(provider)).orElseThrow(() -> new RuntimeException("Provider not found"));
            user.setProvider(existingProvider);
            user.setRole(role);
            userRepository.save(user);
            String authCode = UUID.randomUUID().toString();
            authService.saveAuthorizationCode(authCode, user.getId());
            response.sendRedirect("%s/oauth/callback?authorization_code=%s".formatted(frontendUrl, authCode));
        } else {
            User user = userRepository.findByEmail(email).orElseThrow(() -> new RuntimeException("User not found"));
            String authCode = UUID.randomUUID().toString();
            authService.saveAuthorizationCode(authCode, user.getId());
            response.sendRedirect("%s/oauth/callback?authorization_code=%s".formatted(frontendUrl, authCode));
        }
    }
}
