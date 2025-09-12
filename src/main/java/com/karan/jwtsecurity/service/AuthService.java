package com.karan.jwtsecurity.service;

import com.karan.jwtsecurity.dto.RegisterRequest;
import com.karan.jwtsecurity.entity.User;
import com.karan.jwtsecurity.repository.UserRepository;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Transactional
    public void register(RegisterRequest registerRequest){
        if(userRepository.existsByUsername(registerRequest.getUsername())){
            throw new IllegalArgumentException("Username already exists");
        }
        // if does not exist create a new user
        User user = User.builder()
                .fullName(registerRequest.getFullName())
                .username(registerRequest.getUsername())
                .password(passwordEncoder.encode(registerRequest.getPassword()))
                .role(registerRequest.getRole())

                .build();

        userRepository.save(user);

    }
}
