package com.spring.spring_auth.controllers;

import com.spring.spring_auth.configs.security.services.UserDetailsImpl;
import com.spring.spring_auth.dtos.responses.UserResponse;
import com.spring.spring_auth.repositories.UserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/users/")
public class UserController {

    private final UserRepository userRepository;

    public UserController(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @GetMapping("")
    public UserResponse getUserContext() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated()) {
            throw new IllegalArgumentException("User is not authenticated");
        }
        Object principal = authentication.getPrincipal();
        if (principal instanceof UserDetailsImpl userDetails) {
            if (userRepository.findById(userDetails.getId()).isPresent()) {
                return new UserResponse(
                        userDetails.getId(),
                        userDetails.getUsername(),
                        userDetails.getRole(),
                        userDetails.getCreatedAt()
                );
            }

        } else {
            throw new IllegalArgumentException("Cannot get user context");
        }
        return null;
    }
}
