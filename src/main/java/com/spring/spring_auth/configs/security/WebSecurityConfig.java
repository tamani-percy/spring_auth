package com.spring.spring_auth.configs.security;

import com.spring.spring_auth.configs.security.jwt.JwtAuthenticationProvider;
import com.spring.spring_auth.configs.security.oauth.OAuthSuccessHandler;
import com.spring.spring_auth.configs.security.services.UserDetailsServiceImpl;
import com.spring.spring_auth.repositories.ProviderRepository;
import com.spring.spring_auth.repositories.RoleRepository;
import com.spring.spring_auth.repositories.UserRepository;
import com.spring.spring_auth.services.AuthService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

@Configuration
@EnableMethodSecurity
public class WebSecurityConfig implements WebMvcConfigurer {

    private final UserDetailsServiceImpl userDetailsService;
    private final JwtAuthenticationProvider jwtAuthenticationProvider;

    public WebSecurityConfig(UserDetailsServiceImpl userDetailsService, JwtAuthenticationProvider jwtAuthenticationProvider) {

        this.userDetailsService = userDetailsService;
        this.jwtAuthenticationProvider = jwtAuthenticationProvider;
    }

    @Bean
    public AuthTokenFilter authenticationJwtTokenFilter(ContextUtil contextUtil) {
        return new AuthTokenFilter(jwtAuthenticationProvider, userDetailsService, contextUtil);
    }

    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder());

        return authProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public CookieCsrfTokenRepository cookieCsrfTokenRepository() {
        return CookieCsrfTokenRepository.withHttpOnlyFalse();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, UserRepository userRepository, RoleRepository roleRepository, ProviderRepository providerRepository, AuthService authService, ContextUtil contextUtil) throws Exception {
        http
                .redirectToHttps(Customizer.withDefaults())
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .addFilterBefore(authenticationJwtTokenFilter(contextUtil),
                        UsernamePasswordAuthenticationFilter.class)
                .csrf(AbstractHttpConfigurer::disable)
                .exceptionHandling(exception -> exception.authenticationEntryPoint(new AuthEntryPointJwt()))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

                .authorizeHttpRequests(auth ->
                        auth.requestMatchers(
                                        "/api/v1/auth/login",
                                        "/api/v1/auth/signup",
                                        "/api/v1/auth/admin/",
                                        "/api/v1/auth/oauth-exchange/**"
                                ).permitAll()
                                .requestMatchers("/error").permitAll()
                                .requestMatchers("/favicon.ico").permitAll()
                                .requestMatchers("/oauth2/**").permitAll()
                                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                                .anyRequest().authenticated()
                )
                .oauth2Login((oauth2login) ->
                        oauth2login.successHandler(oAuth2AuthenticationSuccessHandler(userRepository, roleRepository, providerRepository, authService))
                );
        http.authenticationProvider(authenticationProvider());

        return http.build();
    }

    @Bean
    public OAuthSuccessHandler oAuth2AuthenticationSuccessHandler(UserRepository userRepository, RoleRepository roleRepository, ProviderRepository providerRepository, AuthService authService) {
        return new OAuthSuccessHandler(userRepository, roleRepository, providerRepository, authService);
    }

    @Bean
    public UrlBasedCorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOriginPatterns(List.of(
                "http://localhost:5173"
        ));
        config.setAllowedMethods(List.of(
                "GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"
        ));
        config.setAllowedHeaders(List.of(
                "Authorization",
                "Content-Type",
                "X-Requested-With"
        ));
        config.setAllowCredentials(true);
        config.setMaxAge(3600L);
        UrlBasedCorsConfigurationSource source =
                new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }


}
