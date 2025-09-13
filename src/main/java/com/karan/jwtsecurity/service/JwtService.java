package com.karan.jwtsecurity.service;

import com.karan.jwtsecurity.dto.TokenPair;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class JwtService {

    @Value("${app.jwt.secret}")
    private String jwtSecret;

    @Value("${app.jwt.expiration}")
    private long jwtExpirationMs;

    @Value("${app.jwt.refresh-expiration}")
    private long refreshExpirationMs;

    private SecretKey signingKey; // Cache the signing key

    @PostConstruct
    public void init() {
        // Initialize and validate the signing key at startup
        this.signingKey = createSigningKey();
        System.out.println("JWT Service initialized successfully");
        System.out.println("Access token expiration: " + jwtExpirationMs + "ms (" + (jwtExpirationMs/1000/60) + " minutes)");
        System.out.println("Refresh token expiration: " + refreshExpirationMs + "ms (" + (refreshExpirationMs/1000/60/60) + " hours)");
    }

    private SecretKey createSigningKey() {
        try {
            // Validate secret is not null or empty
            if (jwtSecret == null || jwtSecret.trim().isEmpty()) {
                throw new IllegalArgumentException("JWT secret cannot be null or empty");
            }

            byte[] keyBytes;
            System.out.println("JWT Secret length: " + jwtSecret.length());

            try {
                // Try to decode as Base64
                keyBytes = Base64.getDecoder().decode(jwtSecret.trim());
                System.out.println("Successfully decoded Base64 key, length: " + keyBytes.length + " bytes");

                // Validate key length for HS512 (minimum 64 bytes)
                if (keyBytes.length < 64) {
                    throw new IllegalArgumentException(
                            "JWT secret key is too short for HS512. Current: " + keyBytes.length +
                                    " bytes, Required: minimum 64 bytes. Please generate a proper key using: openssl rand -base64 64"
                    );
                }

            } catch (IllegalArgumentException e) {
                if (e.getMessage().contains("JWT secret key is too short")) {
                    throw e; // Re-throw our custom validation error
                }

                // Base64 decoding failed, treat as plain text
                System.out.println("Base64 decoding failed, treating as plain text: " + e.getMessage());
                keyBytes = jwtSecret.trim().getBytes(StandardCharsets.UTF_8);
                System.out.println("Plain text key length: " + keyBytes.length + " bytes");

                // For plain text, we need at least 64 characters for HS512
                if (keyBytes.length < 64) {
                    throw new IllegalArgumentException(
                            "JWT secret is too short. For plain text secrets, minimum 64 characters required for HS512. " +
                                    "Current length: " + keyBytes.length + ". Consider generating a proper Base64 key: openssl rand -base64 64"
                    );
                }
            }

            return Keys.hmacShaKeyFor(keyBytes);

        } catch (Exception e) {
            System.err.println("Failed to create JWT signing key: " + e.getMessage());
            throw new RuntimeException("JWT configuration error: " + e.getMessage(), e);
        }
    }

    // Get cached signing key
    private SecretKey getSigningKey() {
        return this.signingKey;
    }

    // Generate both access and refresh tokens
    public TokenPair generateTokenPair(Authentication authentication) {
        return new TokenPair(generateAccessToken(authentication), generateRefreshToken(authentication));
    }

    // Generate access token
    public String generateAccessToken(Authentication authentication) {
        try {
            UserDetails user = (UserDetails) authentication.getPrincipal();
            Date now = new Date();
            Date expiry = new Date(now.getTime() + jwtExpirationMs);

            String token = Jwts.builder()
                    .setHeaderParam("typ", "JWT")
                    .setSubject(user.getUsername())
                    .setIssuedAt(now)
                    .setExpiration(expiry)
                    .setIssuer("jwt-security-app") // Add issuer
                    .signWith(getSigningKey(), SignatureAlgorithm.HS512)
                    .compact();

            System.out.println("Generated access token for user: " + user.getUsername());
            return token;

        } catch (Exception e) {
            System.err.println("Failed to generate access token: " + e.getMessage());
            throw new RuntimeException("Token generation failed", e);
        }
    }

    // Generate refresh token
    public String generateRefreshToken(Authentication authentication) {
        try {
            UserDetails user = (UserDetails) authentication.getPrincipal();
            Date now = new Date();
            Date expiry = new Date(now.getTime() + refreshExpirationMs);

            String token = Jwts.builder()
                    .setSubject(user.getUsername())
                    .setIssuedAt(now)
                    .setExpiration(expiry)
                    .setIssuer("jwt-security-app") // Add issuer
                    .claim("type", "refresh") // Mark explicitly
                    .signWith(getSigningKey(), SignatureAlgorithm.HS512)
                    .compact();

            System.out.println("Generated refresh token for user: " + user.getUsername());
            return token;

        } catch (Exception e) {
            System.err.println("Failed to generate refresh token: " + e.getMessage());
            throw new RuntimeException("Refresh token generation failed", e);
        }
    }

    // Validate token with detailed error handling
    public boolean validateToken(String token) {
        try {
            if (token == null || token.trim().isEmpty()) {
                System.err.println("Token is null or empty");
                return false;
            }

            // Parse and validate the token
            Jws<Claims> claimsJws = Jwts.parser()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token.trim());

            // Additional validation
            Claims claims = claimsJws.getBody();
            Date expiration = claims.getExpiration();
            Date now = new Date();

            if (expiration.before(now)) {
                System.err.println("Token is expired. Expiration: " + expiration + ", Current: " + now);
                return false;
            }

            System.out.println("Token validation successful for user: " + claims.getSubject());
            return true;

        } catch (ExpiredJwtException e) {
            System.err.println("JWT token is expired: " + e.getMessage());
        } catch (UnsupportedJwtException e) {
            System.err.println("JWT token is unsupported: " + e.getMessage());
        } catch (MalformedJwtException e) {
            System.err.println("JWT token is malformed: " + e.getMessage());
        } catch (SignatureException e) {
            System.err.println("JWT signature validation failed: " + e.getMessage());
            System.err.println("This usually means the token was signed with a different key");
        } catch (IllegalArgumentException e) {
            System.err.println("JWT token is invalid: " + e.getMessage());
        } catch (JwtException e) {
            System.err.println("JWT validation error: " + e.getMessage());
        } catch (Exception e) {
            System.err.println("Unexpected error during token validation: " + e.getMessage());
        }
        return false;
    }

    // Extract username with error handling
    public String getUsernameFromToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token.trim())
                    .getBody();
            return claims.getSubject();
        } catch (JwtException e) {
            System.err.println("Failed to extract username from token: " + e.getMessage());
            throw new RuntimeException("Invalid token", e);
        }
    }

    // Check if token is refresh token
    public boolean isRefreshToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token.trim())
                    .getBody();
            return "refresh".equals(claims.get("type", String.class));
        } catch (JwtException e) {
            System.err.println("Failed to check token type: " + e.getMessage());
            return false;
        }
    }

    // Get token expiration
    public Date getExpirationFromToken(String token) {
        try {
            Claims claims = Jwts.parser()
                    .setSigningKey(getSigningKey())
                    .build()
                    .parseClaimsJws(token.trim())
                    .getBody();
            return claims.getExpiration();
        } catch (JwtException e) {
            System.err.println("Failed to extract expiration from token: " + e.getMessage());
            return null;
        }
    }

    // Check if token is expired
    public boolean isTokenExpired(String token) {
        try {
            Date expiration = getExpirationFromToken(token);
            return expiration != null && expiration.before(new Date());
        } catch (Exception e) {
            return true; // Consider invalid tokens as expired
        }
    }
    public TokenPair generateTokenPairByUsername(String username) {
        Date now = new Date();
        Date accessExpiry = new Date(now.getTime() + jwtExpirationMs);
        Date refreshExpiry = new Date(now.getTime() + refreshExpirationMs);

        String accessToken = Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(accessExpiry)
                .setIssuer("jwt-security-app")
                .signWith(getSigningKey(), SignatureAlgorithm.HS512)
                .compact();

        String refreshToken = Jwts.builder()
                .setHeaderParam("typ", "JWT")
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(refreshExpiry)
                .setIssuer("jwt-security-app")
                .claim("type", "refresh")
                .signWith(getSigningKey(), SignatureAlgorithm.HS512)
                .compact();

        return new TokenPair(accessToken, refreshToken);
    }

}