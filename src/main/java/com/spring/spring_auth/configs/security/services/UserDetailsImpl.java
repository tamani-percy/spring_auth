package com.spring.spring_auth.configs.security.services;

import com.spring.spring_auth.models.Role;
import com.spring.spring_auth.models.User;
import lombok.Getter;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.annotate.JsonIgnore;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serial;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;

@Slf4j
public class UserDetailsImpl implements UserDetails {

    @Serial
    private static final long serialVersionUID = 1L;

    @Getter
    private Long id;

    @Setter
    @Getter
    private String email;

    @Getter
    private Role role;

    @JsonIgnore
    private String password;

    @Getter
    private LocalDateTime createdAt;

    @Setter
    private Map<String, Object> attributes;

    private final Collection<? extends GrantedAuthority> authorities;

    public UserDetailsImpl(Long id, String password, LocalDateTime createdAt, Role role, String email, Collection<? extends GrantedAuthority> authorities) {
        this.authorities = authorities;
        this.id = id;
        this.createdAt = createdAt;
        this.role = role;
        this.password = password;
        this.email = email;
    }

    public static UserDetailsImpl build(User user) {
        List<GrantedAuthority> authorities =
                List.of(new SimpleGrantedAuthority(user.getRole().getRole().name()));

        return new UserDetailsImpl(
                user.getId(),
                user.getPassword(),
                user.getCreatedAt(),
                user.getRole(),
                user.getEmail(),
                authorities
        );
    }

    public static UserDetailsImpl create(User user, Map<String, Object> attributes) {
        UserDetailsImpl userDetails = UserDetailsImpl.build(user);
        userDetails.setAttributes(attributes);
        return userDetails;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return UserDetails.super.isAccountNonExpired();
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        UserDetailsImpl user = (UserDetailsImpl) o;
        return Objects.equals(id, user.id);
    }
}
