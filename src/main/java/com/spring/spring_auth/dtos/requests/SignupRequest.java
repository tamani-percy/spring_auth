package com.spring.spring_auth.dtos.requests;

import lombok.Data;

@Data
public class SignupRequest {
    private String username;
    private String password;
}
