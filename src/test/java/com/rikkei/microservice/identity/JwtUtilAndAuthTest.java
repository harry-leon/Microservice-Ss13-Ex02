package com.rikkei.microservice.identity;

import com.rikkei.microservice.identity.entity.User;
import com.rikkei.microservice.identity.repository.UserRepository;
import com.rikkei.microservice.identity.security.JwtUtil;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.security.Key;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
public class JwtUtilAndAuthTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtUtil jwtUtil;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Value("${jwt-secret}")
    private String jwtSecret;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();
    }

    @Test
    void testGenerateTokenAndValidateClaims() {
        User user = User.builder()
                .username("john_doe")
                .email("john@example.com")
                .password(passwordEncoder.encode("password123"))
                .roles(Set.of("ADMIN"))
                .build();
        user = userRepository.save(user);

        // Generate token
        String token = jwtUtil.generateToken(user);
        assertNotNull(token);
        assertTrue(token.length() > 20);

        // Validate token
        assertTrue(jwtUtil.validateJwtToken(token));
        assertEquals("john_doe", jwtUtil.getUsernameFromJwtToken(token));

        // Parse claims
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        Key key = Keys.hmacShaKeyFor(keyBytes);
        Claims claims = Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();

        // sub claim is username
        assertEquals("john_doe", claims.getSubject());
        // custom role claim
        assertEquals("ADMIN", claims.get("role"));
    }

    @Test
    void testGetTokenEndpoint_Success() throws Exception {
        User user = User.builder()
                .username("alice")
                .email("alice@example.com")
                .password(passwordEncoder.encode("password123"))
                .roles(Set.of("USER"))
                .build();
        userRepository.save(user);

        String token = mockMvc.perform(get("/api/auth/test-token")
                        .param("username", "alice"))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertNotNull(token);
        assertFalse(token.isEmpty());
        assertTrue(jwtUtil.validateJwtToken(token));
        assertEquals("alice", jwtUtil.getUsernameFromJwtToken(token));
    }

    @Test
    void testGetTokenEndpoint_NotFound() throws Exception {
        mockMvc.perform(get("/api/auth/test-token")
                        .param("username", "non_existing_user"))
                .andExpect(status().isNotFound());
    }
}
