package com.karan.jwtsecurity.dto;
import com.karan.jwtsecurity.entity.Role;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@AllArgsConstructor
@Builder
public class RegisterRequest {

    @NotBlank(message = "Full name is required")
    @Size(min = 3, max = 50, message = "Full name must be between 3 to 50 characters")
    private String fullName;

    @NotBlank(message = "Username is required")
    @Size(min = 3, max = 10, message = "Username must be between 3 to 10 characters")
    private String username;

    @NotBlank(message = "Password is required")
    @Size(min = 3, max = 10, message = "Password must be between 3 to 10 characters")
    private String password;

    private Role role;
}
