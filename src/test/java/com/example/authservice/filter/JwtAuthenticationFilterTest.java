package com.example.authservice.filter;

import com.example.authservice.service.RsaJwtService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ActiveProfiles;

import java.io.IOException;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@ActiveProfiles("test")
class JwtAuthenticationFilterTest {

    @Mock
    private RsaJwtService jwtService;

    @Mock
    private HttpServletRequest request;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain filterChain;

    @Mock
    private Claims mockClaims;

    @InjectMocks
    private JwtAuthenticationFilter jwtAuthenticationFilter;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
    }

    @Test
    @DisplayName("Authorization 헤더 없는 경우 테스트")
    void doFilterInternal_NoAuthHeader_SkipsAuthentication() throws ServletException, IOException {
        // Given
        when(request.getHeader("Authorization")).thenReturn(null);

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNull();

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(jwtService);
    }

    @Test
    @DisplayName("Bearer로 시작하지 않는 Authorization 헤더 테스트")
    void doFilterInternal_InvalidAuthHeaderFormat_SkipsAuthentication() throws ServletException, IOException {
        // Given
        when(request.getHeader("Authorization")).thenReturn("Basic sometoken");

        // When
        jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

        // Then
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        assertThat(authentication).isNull();

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(jwtService);
    }

    @Test
    @DisplayName("shouldNotFilter 테스트 - /api/auth/ 경로")
    void shouldNotFilter_AuthPath_ReturnsTrue() {
        // Given
        when(request.getRequestURI()).thenReturn("/api/auth/login");

        // When
        boolean result = jwtAuthenticationFilter.shouldNotFilter(request);

        // Then
        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("shouldNotFilter 테스트 - /actuator/ 경로")
    void shouldNotFilter_ActuatorPath_ReturnsTrue() {
        // Given
        when(request.getRequestURI()).thenReturn("/actuator/health");

        // When
        boolean result = jwtAuthenticationFilter.shouldNotFilter(request);

        // Then
        assertThat(result).isTrue();
    }

    @Test
    @DisplayName("shouldNotFilter 테스트 - 보호된 경로")
    void shouldNotFilter_ProtectedPath_ReturnsFalse() {
        // Given
        when(request.getRequestURI()).thenReturn("/api/protected/resource");

        // When
        boolean result = jwtAuthenticationFilter.shouldNotFilter(request);

        // Then
        assertThat(result).isFalse();
    }
}