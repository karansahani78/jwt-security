package com.karan.jwtsecurity.dto;

import com.karan.jwtsecurity.entity.Role;
import lombok.*;

@Getter
@Setter
@RequiredArgsConstructor
@AllArgsConstructor
@Builder

public class RegisterResponse {


        private Long id;

        private String fullName;

        private String username;

        private Role role;
    }


