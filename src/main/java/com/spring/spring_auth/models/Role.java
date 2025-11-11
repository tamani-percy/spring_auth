package com.spring.spring_auth.models;

import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name="roles")
@AllArgsConstructor
@Getter
@Setter
@NoArgsConstructor
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Enumerated(EnumType.STRING)
    @Column(length = 20)
    private ERole role;
}
