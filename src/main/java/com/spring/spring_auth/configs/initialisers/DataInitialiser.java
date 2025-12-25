package com.spring.spring_auth.configs.initialisers;

import com.spring.spring_auth.models.*;
import com.spring.spring_auth.repositories.ProviderRepository;
import com.spring.spring_auth.repositories.RoleRepository;
import com.spring.spring_auth.repositories.UserRepository;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.List;
import java.util.UUID;

@Configuration
public class DataInitialiser {

    @Value("${sa_email}")
    private String sa_email;
    @Value("${sa_password}")
    private String sa_password;

    @Bean
    CommandLineRunner initRolesAndSuperAdmin(RoleRepository roleRepository,
                                             ProviderRepository providerRepository,
                                             UserRepository userRepository,
                                             PasswordEncoder passwordEncoder) {
        return args -> {
            for (ERole eRole : ERole.values()) {
                if (roleRepository.findByRole(eRole).isEmpty()) {
                    roleRepository.save(new Role(null, eRole));
                }
            }
            for (EProvider eProvider : EProvider.values()) {
                if (providerRepository.findByProvider(eProvider).isEmpty()) {
                    providerRepository.save(new Provider(null, eProvider));
                }
            }

            Provider provider = providerRepository.findByProvider(EProvider.USERNAMEANDPASSWORD).orElseThrow(() -> new RuntimeException("Provider not found"));
            Role superAdminRole = roleRepository.findByRole(ERole.ROLE_SUPER_ADMIN)
                    .orElseThrow(() -> new RuntimeException("SUPER_ADMIN role not found"));

            List<User> superAdmins = userRepository.findByRole(superAdminRole).orElseThrow(() -> new UsernameNotFoundException("No Super Admins found"));

            if (superAdmins.isEmpty()) {
                User superAdmin1 = new User();
                superAdmin1.setEmail(sa_email);
                superAdmin1.setPassword(passwordEncoder.encode(sa_password));
                superAdmin1.setCreatedAt(LocalDateTime.now());
                superAdmin1.setRole(superAdminRole);
                superAdmin1.setProvider(provider);
                userRepository.save(superAdmin1);
                System.out.println("Added superAdmin1");
            }
        };
    }
}
