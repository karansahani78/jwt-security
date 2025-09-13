package com.karan.jwtsecurity.filter;

import com.karan.jwtsecurity.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    // Public endpoints that don't require authentication
    private static final List<String> PUBLIC_URLS = Arrays.asList(
            "/api/auth/login",
            "/api/auth/register",
            "/api/auth/refresh-token",
            "/h2-console",
            "/swagger-ui",
            "/v3/api-docs",
            "/actuator/health"
    );

    @Override
    protected void doFilterInternal(@NonNull HttpServletRequest request,
                                    @NonNull HttpServletResponse response,
                                    @NonNull FilterChain filterChain) throws ServletException, IOException {

        try {
            // Skip JWT processing for public endpoints
            if (isPublicEndpoint(request)) {
                filterChain.doFilter(request, response);
                return;
            }

            // 1️⃣ Get the Authorization header from the request
            final String authHeader = request.getHeader("Authorization");

            // Log request details for debugging
            System.out.println("Processing request: " + request.getMethod() + " " + request.getRequestURI());
            System.out.println("Authorization header present: " + (authHeader != null));

            // 2️⃣ Check if the header is present and starts with "Bearer "
            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                System.out.println("No valid Authorization header found");
                filterChain.doFilter(request, response);
                return;
            }

            // 3️⃣ Extract the token by removing "Bearer " prefix
            final String token = authHeader.substring(7).trim();

            if (token.isEmpty()) {
                System.out.println("Empty token after Bearer prefix");
                filterChain.doFilter(request, response);
                return;
            }

            System.out.println("Extracted token: " + token.substring(0, Math.min(20, token.length())) + "...");

            // 4️⃣ Validate the token
            if (!jwtService.validateToken(token)) {
                System.out.println("Token validation failed");
                filterChain.doFilter(request, response);
                return;
            }

            // 5️⃣ Extract username from token
            String username = null;
            try {
                username = jwtService.getUsernameFromToken(token);
                System.out.println("Extracted username from token: " + username);
            } catch (Exception e) {
                System.err.println("Failed to extract username from token: " + e.getMessage());
                filterChain.doFilter(request, response);
                return;
            }

            // 6️⃣ If username is not null and SecurityContext does not already have an authentication
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                try {
                    // Load user details using UserDetailsService
                    UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                    System.out.println("Loaded user details for: " + userDetails.getUsername());

                    // Additional token validation (optional but recommended)
                    if (isTokenValidForUser(token, userDetails)) {
                        // 7️⃣ Create an authentication token and set it in the context
                        UsernamePasswordAuthenticationToken authentication =
                                new UsernamePasswordAuthenticationToken(
                                        userDetails,
                                        null,
                                        userDetails.getAuthorities()
                                );

                        // Set additional details
                        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                        SecurityContextHolder.getContext().setAuthentication(authentication);
                        System.out.println("Successfully authenticated user: " + username);
                    } else {
                        System.out.println("Token is not valid for user: " + username);
                    }

                } catch (UsernameNotFoundException e) {
                    System.err.println("User not found: " + username + " - " + e.getMessage());
                } catch (Exception e) {
                    System.err.println("Error loading user details: " + e.getMessage());
                }
            } else if (username == null) {
                System.out.println("Username is null, cannot authenticate");
            } else {
                System.out.println("User already authenticated: " + SecurityContextHolder.getContext().getAuthentication().getName());
            }

        } catch (Exception e) {
            System.err.println("Unexpected error in JWT filter: " + e.getMessage());
            e.printStackTrace();
            // Clear security context on error
            SecurityContextHolder.clearContext();
        }

        // 8️⃣ Continue with the filter chain
        filterChain.doFilter(request, response);
    }

    /**
     * Check if the current request is for a public endpoint
     */
    private boolean isPublicEndpoint(HttpServletRequest request) {
        String requestPath = request.getRequestURI();
        return PUBLIC_URLS.stream().anyMatch(publicUrl ->
                requestPath.startsWith(request.getContextPath() + publicUrl) ||
                        requestPath.startsWith(publicUrl)
        );
    }

    /**
     * Additional validation to ensure token is still valid for the user
     */
    private boolean isTokenValidForUser(String token, UserDetails userDetails) {
        try {
            // Check if token is expired
            if (jwtService.isTokenExpired(token)) {
                System.out.println("Token is expired for user: " + userDetails.getUsername());
                return false;
            }

            // Check if username from token matches loaded user
            String tokenUsername = jwtService.getUsernameFromToken(token);
            if (!tokenUsername.equals(userDetails.getUsername())) {
                System.out.println("Token username doesn't match user details");
                return false;
            }

            // Check if user account is still enabled
            if (!userDetails.isEnabled()) {
                System.out.println("User account is disabled: " + userDetails.getUsername());
                return false;
            }

            // Check if user account is not locked
            if (!userDetails.isAccountNonLocked()) {
                System.out.println("User account is locked: " + userDetails.getUsername());
                return false;
            }

            // Check if user account is not expired
            if (!userDetails.isAccountNonExpired()) {
                System.out.println("User account is expired: " + userDetails.getUsername());
                return false;
            }

            // Check if credentials are not expired
            if (!userDetails.isCredentialsNonExpired()) {
                System.out.println("User credentials are expired: " + userDetails.getUsername());
                return false;
            }

            return true;

        } catch (Exception e) {
            System.err.println("Error validating token for user: " + e.getMessage());
            return false;
        }
    }

    /**
     * Skip filter for certain requests (like WebSocket upgrades, static resources, etc.)
     */
    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        String path = request.getRequestURI();

        // Skip filtering for static resources
        if (path.startsWith("/static/") ||
                path.startsWith("/css/") ||
                path.startsWith("/js/") ||
                path.startsWith("/images/") ||
                path.endsWith(".ico")) {
            return true;
        }

        // Skip filtering for WebSocket connections
        if ("websocket".equalsIgnoreCase(request.getHeader("Upgrade"))) {
            return true;
        }

        return false;
    }
}