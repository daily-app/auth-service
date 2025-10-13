package com.example.authservice.service;

import com.example.authservice.dto.AuthResponse;
import com.example.authservice.dto.LoginRequest;
import com.example.authservice.dto.RegisterRequest;
import com.example.authservice.entity.User;
import com.example.authservice.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
class AuthServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private RsaJwtService jwtService;

    @InjectMocks
    private AuthService authService;

    private User testUser;
    private RegisterRequest registerRequest;
    private LoginRequest loginRequest;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setId(1L);
        testUser.setEmail("test@example.com");
        testUser.setPassword("encodedPassword");
        testUser.setName("Test User");
        testUser.setRoles(Set.of("USER"));

        registerRequest = new RegisterRequest();
        registerRequest.setEmail("test@example.com");
        registerRequest.setPassword("password123");
        registerRequest.setName("Test User");

        loginRequest = new LoginRequest();
        loginRequest.setEmail("test@example.com");
        loginRequest.setPassword("password123");
    }

    @Test
    @DisplayName("회원가입 성공 테스트")
    void register_Success() {
        // Given
        when(userRepository.existsByEmail(registerRequest.getEmail())).thenReturn(false);
        when(passwordEncoder.encode(registerRequest.getPassword())).thenReturn("encodedPassword");
        when(userRepository.save(any(User.class))).thenReturn(testUser);
        when(jwtService.generateAccessToken(testUser.getEmail(), testUser.getName(), testUser.getRoles()))
                .thenReturn("accessToken");
        when(jwtService.generateRefreshToken(testUser.getEmail()))
                .thenReturn("refreshToken");

        // When
        AuthResponse response = authService.register(registerRequest);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getAccessToken()).isEqualTo("accessToken");
        assertThat(response.getRefreshToken()).isEqualTo("refreshToken");
        assertThat(response.getEmail()).isEqualTo(testUser.getEmail());
        assertThat(response.getName()).isEqualTo(testUser.getName());
        assertThat(response.getRoles()).isEqualTo(testUser.getRoles());

        verify(userRepository).existsByEmail(registerRequest.getEmail());
        verify(passwordEncoder).encode(registerRequest.getPassword());
        verify(userRepository).save(any(User.class));
        verify(jwtService).generateAccessToken(testUser.getEmail(), testUser.getName(), testUser.getRoles());
        verify(jwtService).generateRefreshToken(testUser.getEmail());
    }

    @Test
    @DisplayName("회원가입 실패 - 이미 존재하는 이메일")
    void register_EmailAlreadyExists_ThrowsException() {
        // Given
        when(userRepository.existsByEmail(registerRequest.getEmail())).thenReturn(true);

        // When & Then
        assertThatThrownBy(() -> authService.register(registerRequest))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("이미 존재하는 이메일입니다");

        verify(userRepository).existsByEmail(registerRequest.getEmail());
        verify(passwordEncoder, never()).encode(anyString());
        verify(userRepository, never()).save(any(User.class));
    }

    @Test
    @DisplayName("로그인 성공 테스트")
    void login_Success() {
        // Given
        when(userRepository.findByEmail(loginRequest.getEmail())).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(loginRequest.getPassword(), testUser.getPassword())).thenReturn(true);
        when(jwtService.generateAccessToken(testUser.getEmail(), testUser.getName(), testUser.getRoles()))
                .thenReturn("accessToken");
        when(jwtService.generateRefreshToken(testUser.getEmail()))
                .thenReturn("refreshToken");

        // When
        AuthResponse response = authService.login(loginRequest);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getAccessToken()).isEqualTo("accessToken");
        assertThat(response.getRefreshToken()).isEqualTo("refreshToken");
        assertThat(response.getEmail()).isEqualTo(testUser.getEmail());
        assertThat(response.getName()).isEqualTo(testUser.getName());
        assertThat(response.getRoles()).isEqualTo(testUser.getRoles());

        verify(userRepository).findByEmail(loginRequest.getEmail());
        verify(passwordEncoder).matches(loginRequest.getPassword(), testUser.getPassword());
        verify(jwtService).generateAccessToken(testUser.getEmail(), testUser.getName(), testUser.getRoles());
        verify(jwtService).generateRefreshToken(testUser.getEmail());
    }

    @Test
    @DisplayName("로그인 실패 - 존재하지 않는 사용자")
    void login_UserNotFound_ThrowsException() {
        // Given
        when(userRepository.findByEmail(loginRequest.getEmail())).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> authService.login(loginRequest))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("존재하지 않는 사용자입니다");

        verify(userRepository).findByEmail(loginRequest.getEmail());
        verify(passwordEncoder, never()).matches(anyString(), anyString());
    }

    @Test
    @DisplayName("로그인 실패 - 비밀번호 불일치")
    void login_InvalidPassword_ThrowsException() {
        // Given
        when(userRepository.findByEmail(loginRequest.getEmail())).thenReturn(Optional.of(testUser));
        when(passwordEncoder.matches(loginRequest.getPassword(), testUser.getPassword())).thenReturn(false);

        // When & Then
        assertThatThrownBy(() -> authService.login(loginRequest))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("비밀번호가 일치하지 않습니다");

        verify(userRepository).findByEmail(loginRequest.getEmail());
        verify(passwordEncoder).matches(loginRequest.getPassword(), testUser.getPassword());
        verify(jwtService, never()).generateAccessToken(anyString(), any());
    }

    @Test
    @DisplayName("토큰 갱신 성공 테스트")
    void refreshToken_Success() {
        // Given
        String refreshToken = "validRefreshToken";
        when(jwtService.isTokenValid(refreshToken)).thenReturn(true);
        when(jwtService.isTokenExpired(refreshToken)).thenReturn(false);
        when(jwtService.getTokenType(refreshToken)).thenReturn("refresh");
        when(jwtService.extractEmail(refreshToken)).thenReturn(testUser.getEmail());
        when(userRepository.findByEmail(testUser.getEmail())).thenReturn(Optional.of(testUser));
        when(jwtService.generateAccessToken(testUser.getEmail(), testUser.getName(), testUser.getRoles()))
                .thenReturn("newAccessToken");
        when(jwtService.generateRefreshToken(testUser.getEmail()))
                .thenReturn("newRefreshToken");

        // When
        AuthResponse response = authService.refreshToken(refreshToken);

        // Then
        assertThat(response).isNotNull();
        assertThat(response.getAccessToken()).isEqualTo("newAccessToken");
        assertThat(response.getRefreshToken()).isEqualTo("newRefreshToken");
        assertThat(response.getEmail()).isEqualTo(testUser.getEmail());

        verify(jwtService).isTokenValid(refreshToken);
        verify(jwtService).isTokenExpired(refreshToken);
        verify(jwtService).getTokenType(refreshToken);
        verify(jwtService).extractEmail(refreshToken);
        verify(userRepository).findByEmail(testUser.getEmail());
    }

    @Test
    @DisplayName("토큰 갱신 실패 - 유효하지 않은 토큰")
    void refreshToken_InvalidToken_ThrowsException() {
        // Given
        String invalidToken = "invalidToken";
        when(jwtService.isTokenValid(invalidToken)).thenReturn(false);

        // When & Then
        assertThatThrownBy(() -> authService.refreshToken(invalidToken))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("유효하지 않은 리프레시 토큰입니다");

        verify(jwtService).isTokenValid(invalidToken);
    }

    @Test
    @DisplayName("토큰 갱신 실패 - 만료된 토큰")
    void refreshToken_ExpiredToken_ThrowsException() {
        // Given
        String expiredToken = "expiredToken";
        when(jwtService.isTokenValid(expiredToken)).thenReturn(true);
        when(jwtService.isTokenExpired(expiredToken)).thenReturn(true);

        // When & Then
        assertThatThrownBy(() -> authService.refreshToken(expiredToken))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("유효하지 않은 리프레시 토큰입니다");

        verify(jwtService).isTokenValid(expiredToken);
        verify(jwtService).isTokenExpired(expiredToken);
    }

    @Test
    @DisplayName("토큰 갱신 실패 - 잘못된 토큰 타입")
    void refreshToken_WrongTokenType_ThrowsException() {
        // Given
        String accessToken = "accessToken";
        when(jwtService.isTokenValid(accessToken)).thenReturn(true);
        when(jwtService.isTokenExpired(accessToken)).thenReturn(false);
        when(jwtService.getTokenType(accessToken)).thenReturn("access");

        // When & Then
        assertThatThrownBy(() -> authService.refreshToken(accessToken))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("리프레시 토큰이 아닙니다");

        verify(jwtService).getTokenType(accessToken);
    }

    @Test
    @DisplayName("토큰 갱신 실패 - 존재하지 않는 사용자")
    void refreshToken_UserNotFound_ThrowsException() {
        // Given
        String refreshToken = "validRefreshToken";
        when(jwtService.isTokenValid(refreshToken)).thenReturn(true);
        when(jwtService.isTokenExpired(refreshToken)).thenReturn(false);
        when(jwtService.getTokenType(refreshToken)).thenReturn("refresh");
        when(jwtService.extractEmail(refreshToken)).thenReturn("nonexistent@example.com");
        when(userRepository.findByEmail("nonexistent@example.com")).thenReturn(Optional.empty());

        // When & Then
        assertThatThrownBy(() -> authService.refreshToken(refreshToken))
                .isInstanceOf(RuntimeException.class)
                .hasMessage("존재하지 않는 사용자입니다");

        verify(userRepository).findByEmail("nonexistent@example.com");
    }
}