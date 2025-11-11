package com.spring.spring_auth.repositories;

import com.spring.spring_auth.models.EProvider;
import com.spring.spring_auth.models.ERole;
import com.spring.spring_auth.models.Provider;
import com.spring.spring_auth.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ProviderRepository extends JpaRepository<Provider, Long> {
    Optional<Provider> findByProvider(EProvider provider);

}
