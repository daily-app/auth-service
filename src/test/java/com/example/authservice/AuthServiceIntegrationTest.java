package com.example.authservice;

import com.example.authservice.dto.AuthResponse;
import com.example.authservice.dto.LoginRequest;
import com.example.authservice.dto.RegisterRequest;
import com.example.authservice.entity.User;
import com.example.authservice.repository.UserRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.MOCK)
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Transactional
class AuthServiceIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    private RegisterRequest registerRequest;
    private LoginRequest loginRequest;

    @BeforeEach
    void setUp() {
        userRepository.deleteAll();

        registerRequest = new RegisterRequest();
        registerRequest.setEmail("integration@example.com");
        registerRequest.setPassword("password123");
        registerRequest.setName("Integration Test User");

        loginRequest = new LoginRequest();
        loginRequest.setEmail("integration@example.com");
        loginRequest.setPassword("password123");
    }

    @Test
    @DisplayName("전체 회원가입 플로우 통합 테스트")
    void fullRegistrationFlow_Success() throws Exception {
        // When - 회원가입
        MvcResult result = mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.email").value("integration@example.com"))
                .andExpect(jsonPath("$.data.name").value("Integration Test User"))
                .andReturn();

        // Then - 데이터베이스 확인
        assertThat(userRepository.existsByEmail("integration@example.com")).isTrue();
        User savedUser = userRepository.findByEmail("integration@example.com").orElseThrow();
        assertThat(savedUser.getName()).isEqualTo("Integration Test User");
        assertThat(savedUser.getRoles()).containsExactly("USER");
        assertThat(passwordEncoder.matches("password123", savedUser.getPassword())).isTrue();

        // 응답에서 토큰 추출
        String responseJson = result.getResponse().getContentAsString();
        assertThat(responseJson).contains("accessToken");
        assertThat(responseJson).contains("refreshToken");
    }

    @Test
    @DisplayName("전체 로그인 플로우 통합 테스트")
    void fullLoginFlow_Success() throws Exception {
        // Given - 사용자 생성
        User user = new User();
        user.setEmail("integration@example.com");
        user.setPassword(passwordEncoder.encode("password123"));
        user.setName("Integration Test User");
        user.setRoles(Set.of("USER"));
        userRepository.save(user);

        // When - 로그인
        MvcResult result = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.email").value("integration@example.com"))
                .andReturn();

        // Then - 토큰 확인
        String responseJson = result.getResponse().getContentAsString();
        assertThat(responseJson).contains("accessToken");
        assertThat(responseJson).contains("refreshToken");
    }

    @Test
    @DisplayName("토큰 갱신 플로우 통합 테스트")
    void fullRefreshTokenFlow_Success() throws Exception {
        // Given - 사용자 등록 및 로그인으로 토큰 획득
        User user = new User();
        user.setEmail("integration@example.com");
        user.setPassword(passwordEncoder.encode("password123"));
        user.setName("Integration Test User");
        user.setRoles(Set.of("USER"));
        userRepository.save(user);

        // 로그인으로 리프레시 토큰 획득
        MvcResult loginResult = mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andExpect(status().isOk())
                .andReturn();

        String loginResponse = loginResult.getResponse().getContentAsString();
        AuthResponse authResponse = objectMapper.readValue(
                objectMapper.readTree(loginResponse).get("data").toString(),
                AuthResponse.class
        );

        // When - 토큰 갱신
        mockMvc.perform(post("/api/auth/refresh")
                        .header("Authorization", "Bearer " + authResponse.getRefreshToken()))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.data.email").value("integration@example.com"));
    }

    @Test
    @DisplayName("중복 이메일 회원가입 실패 통합 테스트")
    void duplicateEmailRegistration_Fails() throws Exception {
        // Given - 첫 번째 사용자 등록
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andExpect(status().isOk());

        // When - 같은 이메일로 재등록 시도
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("이미 존재하는 이메일입니다"));

        // Then - 데이터베이스에는 하나만 존재
        assertThat(userRepository.count()).isEqualTo(1);
    }

    @Test
    @DisplayName("잘못된 비밀번호로 로그인 실패 통합 테스트")
    void loginWithWrongPassword_Fails() throws Exception {
        // Given - 사용자 생성
        User user = new User();
        user.setEmail("integration@example.com");
        user.setPassword(passwordEncoder.encode("correctPassword"));
        user.setName("Integration Test User");
        user.setRoles(Set.of("USER"));
        userRepository.save(user);

        // When - 잘못된 비밀번호로 로그인
        loginRequest.setPassword("wrongPassword");
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("비밀번호가 일치하지 않습니다"));
    }

    @Test
    @DisplayName("존재하지 않는 사용자 로그인 실패 통합 테스트")
    void loginNonExistentUser_Fails() throws Exception {
        // When - 존재하지 않는 사용자로 로그인
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("존재하지 않는 사용자입니다"));
    }

    @Test
    @DisplayName("헬스체크 엔드포인트 통합 테스트")
    void healthCheck_Success() throws Exception {
        // When & Then
        mockMvc.perform(get("/api/auth/health"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Auth Service is running"))
                .andExpect(jsonPath("$.data").value("OK"));
    }
}