package com.rikkei.microservice.identity.controller;

import com.rikkei.microservice.identity.dto.JwtResponse;
import com.rikkei.microservice.identity.dto.LoginRequest;
import com.rikkei.microservice.identity.dto.RegisterRequest;
import com.rikkei.microservice.identity.entity.User;
import com.rikkei.microservice.identity.repository.UserRepository;
import com.rikkei.microservice.identity.security.JwtUtil;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final PasswordEncoder encoder;
    private final JwtUtil jwtUtil;

    /**
     * API GET /api/auth/test-token?username={name}
     * Tìm User trong Database (dữ liệu đã tạo ở Bài 1).
     * Nếu tồn tại, dùng JwtUtil để tạo và trả về chuỗi JWT.
     */
    @GetMapping("/test-token")
    public ResponseEntity<?> testToken(@RequestParam("username") String username) {
        Optional<User> userOptional = userRepository.findByUsername(username);
        if (userOptional.isEmpty()) {
            return ResponseEntity.status(404).body(Map.of("message", "User not found with username: " + username));
        }

        User user = userOptional.get();
        String token = jwtUtil.generateToken(user);
        return ResponseEntity.ok(token);
    }

    @PostMapping("/login")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword())
        );

        SecurityContextHolder.getContext().setAuthentication(authentication);

        User userDetails = (User) authentication.getPrincipal();
        String jwt = jwtUtil.generateToken(userDetails);

        return ResponseEntity.ok(JwtResponse.builder()
                .token(jwt)
                .tokenType("Bearer")
                .id(userDetails.getId())
                .username(userDetails.getUsername())
                .email(userDetails.getEmail())
                .roles(userDetails.getRoles())
                .build());
    }

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest registerRequest) {
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            return ResponseEntity.badRequest().body(Map.of("message", "Error: Username is already taken!"));
        }

        if (userRepository.existsByEmail(registerRequest.getEmail())) {
            return ResponseEntity.badRequest().body(Map.of("message", "Error: Email is already in use!"));
        }

        Set<String> roles = registerRequest.getRoles();
        if (roles == null || roles.isEmpty()) {
            roles = new HashSet<>();
            roles.add("USER");
        }

        User user = User.builder()
                .username(registerRequest.getUsername())
                .email(registerRequest.getEmail())
                .password(encoder.encode(registerRequest.getPassword()))
                .roles(roles)
                .build();

        userRepository.save(user);

        return ResponseEntity.ok(Map.of("message", "User registered successfully!"));
    }
}
