package com.karan.jwtsecurity.controller;

import com.karan.jwtsecurity.dto.RegisterRequest;
import com.karan.jwtsecurity.service.AuthService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
private final AuthService authService;

@PostMapping
    public ResponseEntity<?> register(@RequestBody RegisterRequest registerRequest){
    authService.register(registerRequest);
        return ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully");
}
}
