package com.karan.jwtsecurity.service;

import com.karan.jwtsecurity.dto.LoginRequest;
import com.karan.jwtsecurity.dto.RefreshTokenRequest;
import com.karan.jwtsecurity.dto.RegisterRequest;
import com.karan.jwtsecurity.dto.TokenPair;
import com.karan.jwtsecurity.entity.User;
import com.karan.jwtsecurity.repository.UserRepository;
import jakarta.transaction.Transactional;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

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
    // login request
    public TokenPair login(LoginRequest loginRequest){
        Authentication authentication =  authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.getUsername(),
                        loginRequest.getPassword()
                )
        );
        // set authentication in security context
        SecurityContextHolder.getContext().setAuthentication(authentication);

        // generate the token pair
        return jwtService.generateTokenPair(authentication);
    }
    // refresh token
    @Transactional
    public TokenPair refreshToken(RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();

        // Validate token type
        if (!jwtService.isRefreshToken(refreshToken)) {
            throw new IllegalArgumentException("Invalid refresh token type");
        }

        // Check if token is expired
        if (jwtService.isTokenExpired(refreshToken)) {
            throw new IllegalArgumentException("Refresh token expired. Please login again.");
        }

        // Extract username from refresh token
        String username = jwtService.getUsernameFromToken(refreshToken);

        // Generate new token pair (access + refresh)
        return jwtService.generateTokenPairByUsername(username);
    }



}
