package com.spring.spring_auth.configs.initialisers;

import com.spring.spring_auth.models.*;
import com.spring.spring_auth.repositories.ProviderRepository;
import com.spring.spring_auth.repositories.RoleRepository;
import com.spring.spring_auth.repositories.UserRepository;
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
                superAdmin1.setUsername("sa_" + UUID.randomUUID());
                superAdmin1.setPassword(passwordEncoder.encode("supersecurepassword"));
                superAdmin1.setCreatedAt(LocalDateTime.now());
                superAdmin1.setRole(superAdminRole);
                superAdmin1.setProvider(provider);
                userRepository.save(superAdmin1);
            }

            if (superAdmins.size() == 1) {
                User superAdmin2 = new User();
                superAdmin2.setUsername("sa_" + UUID.randomUUID());
                superAdmin2.setPassword(passwordEncoder.encode("supersecurepassword2"));
                superAdmin2.setCreatedAt(LocalDateTime.now());
                superAdmin2.setRole(superAdminRole);
                superAdmin2.setProvider(provider);
                userRepository.save(superAdmin2);
            }

            if (superAdmins.size() >= 2) {
                System.out.println("⚠️ Maximum number of SUPER_ADMIN users already exists (" + superAdmins.size() + "). No new SUPER_ADMIN created.");
            }
        };
    }
}
