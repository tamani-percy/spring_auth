package com.spring.spring_auth.repositories;

import com.spring.spring_auth.models.Role;
import com.spring.spring_auth.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    Boolean existsByUsername(String username);

    Optional<List<User>> findByRole(Role role);
}
