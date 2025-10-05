package com.example.authservice.controller;

import com.example.authservice.dto.AuthResponse;
import com.example.authservice.dto.LoginRequest;
import com.example.authservice.dto.RegisterRequest;
import com.example.authservice.service.AuthService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Set;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AuthController.class)
@ActiveProfiles("test")
class AuthControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private AuthService authService;

    private RegisterRequest registerRequest;
    private LoginRequest loginRequest;
    private AuthResponse authResponse;

    @BeforeEach
    void setUp() {
        registerRequest = new RegisterRequest();
        registerRequest.setEmail("test@example.com");
        registerRequest.setPassword("password123");
        registerRequest.setName("Test User");

        loginRequest = new LoginRequest();
        loginRequest.setEmail("test@example.com");
        loginRequest.setPassword("password123");

        authResponse = new AuthResponse(
                "accessToken",
                "refreshToken",
                "test@example.com",
                "Test User",
                Set.of("USER")
        );
    }

    @Test
    @DisplayName("회원가입 성공 테스트")
    void register_Success() throws Exception {
        // Given
        when(authService.register(any(RegisterRequest.class))).thenReturn(authResponse);

        // When & Then
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("회원가입이 완료되었습니다"))
                .andExpect(jsonPath("$.data.accessToken").value("accessToken"))
                .andExpect(jsonPath("$.data.refreshToken").value("refreshToken"))
                .andExpect(jsonPath("$.data.email").value("test@example.com"))
                .andExpect(jsonPath("$.data.name").value("Test User"));
    }

    @Test
    @DisplayName("회원가입 실패 - 잘못된 이메일 형식")
    void register_InvalidEmail_ReturnsBadRequest() throws Exception {
        // Given
        registerRequest.setEmail("invalid-email");

        // When & Then
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    @DisplayName("회원가입 실패 - 빈 필드")
    void register_EmptyFields_ReturnsBadRequest() throws Exception {
        // Given
        registerRequest.setEmail("");
        registerRequest.setPassword("");
        registerRequest.setName("");

        // When & Then
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    @DisplayName("회원가입 실패 - 짧은 비밀번호")
    void register_ShortPassword_ReturnsBadRequest() throws Exception {
        // Given
        registerRequest.setPassword("123");

        // When & Then
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false));
    }

    @Test
    @DisplayName("회원가입 실패 - 서비스 예외")
    void register_ServiceException_ReturnsBadRequest() throws Exception {
        // Given
        when(authService.register(any(RegisterRequest.class)))
                .thenThrow(new RuntimeException("이미 존재하는 이메일입니다"));

        // When & Then
        mockMvc.perform(post("/api/auth/register")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerRequest)))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("이미 존재하는 이메일입니다"));
    }

    @Test
    @DisplayName("로그인 성공 테스트")
    void login_Success() throws Exception {
        // Given
        when(authService.login(any(LoginRequest.class))).thenReturn(authResponse);

        // When & Then
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("로그인이 완료되었습니다"))
                .andExpect(jsonPath("$.data.accessToken").value("accessToken"))
                .andExpect(jsonPath("$.data.refreshToken").value("refreshToken"));
    }

    @Test
    @DisplayName("로그인 실패 - 잘못된 자격증명")
    void login_InvalidCredentials_ReturnsBadRequest() throws Exception {
        // Given
        when(authService.login(any(LoginRequest.class)))
                .thenThrow(new RuntimeException("비밀번호가 일치하지 않습니다"));

        // When & Then
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("비밀번호가 일치하지 않습니다"));
    }

    @Test
    @DisplayName("토큰 갱신 성공 테스트")
    void refreshToken_Success() throws Exception {
        // Given
        when(authService.refreshToken(anyString())).thenReturn(authResponse);

        // When & Then
        mockMvc.perform(post("/api/auth/refresh")
                        .header("Authorization", "Bearer refreshToken"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("토큰이 갱신되었습니다"))
                .andExpect(jsonPath("$.data.accessToken").value("accessToken"));
    }

    @Test
    @DisplayName("토큰 갱신 실패 - Authorization 헤더 없음")
    void refreshToken_NoAuthHeader_ReturnsBadRequest() throws Exception {
        // When & Then
        mockMvc.perform(post("/api/auth/refresh"))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("리프레시 토큰이 필요합니다"));
    }

    @Test
    @DisplayName("토큰 갱신 실패 - 잘못된 헤더 형식")
    void refreshToken_InvalidHeaderFormat_ReturnsBadRequest() throws Exception {
        // When & Then
        mockMvc.perform(post("/api/auth/refresh")
                        .header("Authorization", "Invalid token"))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("리프레시 토큰이 필요합니다"));
    }

    @Test
    @DisplayName("토큰 갱신 실패 - 서비스 예외")
    void refreshToken_ServiceException_ReturnsBadRequest() throws Exception {
        // Given
        when(authService.refreshToken(anyString()))
                .thenThrow(new RuntimeException("유효하지 않은 리프레시 토큰입니다"));

        // When & Then
        mockMvc.perform(post("/api/auth/refresh")
                        .header("Authorization", "Bearer invalidToken"))
                .andDo(print())
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.success").value(false))
                .andExpect(jsonPath("$.message").value("유효하지 않은 리프레시 토큰입니다"));
    }

    @Test
    @DisplayName("헬스체크 테스트")
    void health_ReturnsOk() throws Exception {
        // When & Then
        mockMvc.perform(get("/api/auth/health"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.success").value(true))
                .andExpect(jsonPath("$.message").value("Auth Service is running"))
                .andExpect(jsonPath("$.data").value("OK"));
    }

    @Test
    @DisplayName("잘못된 JSON 형식 테스트")
    void invalidJson_ReturnsBadRequest() throws Exception {
        // When & Then
        mockMvc.perform(post("/api/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{ invalid json }"))
                .andDo(print())
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Content-Type 누락 테스트")
    void missingContentType_ReturnsUnsupportedMediaType() throws Exception {
        // When & Then
        mockMvc.perform(post("/api/auth/login")
                        .content(objectMapper.writeValueAsString(loginRequest)))
                .andDo(print())
                .andExpect(status().isUnsupportedMediaType());
    }
}