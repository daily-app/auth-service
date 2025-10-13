package com.example.authservice.service;

import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.test.context.ActiveProfiles;

import java.security.NoSuchAlgorithmException;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;

@ActiveProfiles("test")
class RsaJwtServiceTest {

    private RsaJwtService rsaJwtService;
    private final long accessTokenExpiration = 900000L;
    private final long refreshTokenExpiration = 604800000L;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        rsaJwtService = new RsaJwtService();
        // 테스트를 위해 수동으로 필드 설정
        setField(rsaJwtService, "accessTokenExpiration", accessTokenExpiration);
        setField(rsaJwtService, "refreshTokenExpiration", refreshTokenExpiration);
        rsaJwtService.init();
    }

    // 리플렉션을 사용하여 private 필드 설정
    private void setField(Object target, String fieldName, Object value) {
        try {
            var field = target.getClass().getDeclaredField(fieldName);
            field.setAccessible(true);
            field.set(target, value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    @DisplayName("RSA 키 페어 생성 테스트")
    void init_GeneratesRsaKeyPair() {
        // Then
        assertThat(rsaJwtService.getPublicKey()).isNotNull();
        assertThat(rsaJwtService.getPublicKeyAsString()).isNotNull();
        assertThat(rsaJwtService.getPublicKeyAsString()).isNotEmpty();
    }

    @Test
    @DisplayName("Access Token 생성 테스트")
    void generateAccessToken_Success() {
        // Given
        String email = "test@example.com";
        String name = "Test User";
        Set<String> roles = Set.of("USER", "ADMIN");

        // When
        String token = rsaJwtService.generateAccessToken(email, name, roles);

        // Then
        assertThat(token).isNotNull();
        assertThat(token).isNotEmpty();
        assertThat(token.split("\\.")).hasSize(3); // JWT는 3개 부분으로 구성
    }

    @Test
    @DisplayName("Refresh Token 생성 테스트")
    void generateRefreshToken_Success() {
        // Given
        String email = "test@example.com";

        // When
        String token = rsaJwtService.generateRefreshToken(email);

        // Then
        assertThat(token).isNotNull();
        assertThat(token).isNotEmpty();
        assertThat(token.split("\\.")).hasSize(3);
    }

    @Test
    @DisplayName("토큰에서 이메일 추출 테스트")
    void extractEmail_Success() {
        // Given
        String email = "test@example.com";
        String name = "Test User";
        Set<String> roles = Set.of("USER");
        String token = rsaJwtService.generateAccessToken(email, name, roles);

        // When
        String extractedEmail = rsaJwtService.extractEmail(token);

        // Then
        assertThat(extractedEmail).isEqualTo(email);
    }

    @Test
    @DisplayName("토큰에서 Claims 추출 테스트")
    void extractClaims_Success() {
        // Given
        String email = "test@example.com";
        String name = "Test User";
        Set<String> roles = Set.of("USER", "ADMIN");
        String token = rsaJwtService.generateAccessToken(email, name, roles);

        // When
        Claims claims = rsaJwtService.extractClaims(token);

        // Then
        assertThat(claims.getSubject()).isEqualTo(email);
        assertThat(claims.get("name")).isEqualTo(name);
        assertThat(claims.get("roles")).isNotNull();
        assertThat(claims.get("type")).isEqualTo("access");
    }

    @Test
    @DisplayName("유효한 토큰 검증 테스트")
    void isTokenValid_ValidToken_ReturnsTrue() {
        // Given
        String email = "test@example.com";
        String name = "Test User";
        Set<String> roles = Set.of("USER");
        String token = rsaJwtService.generateAccessToken(email, name, roles);

        // When
        boolean isValid = rsaJwtService.isTokenValid(token);

        // Then
        assertThat(isValid).isTrue();
    }

    @Test
    @DisplayName("유효하지 않은 토큰 검증 테스트")
    void isTokenValid_InvalidToken_ReturnsFalse() {
        // Given
        String invalidToken = "invalid.token.here";

        // When
        boolean isValid = rsaJwtService.isTokenValid(invalidToken);

        // Then
        assertThat(isValid).isFalse();
    }

    @Test
    @DisplayName("토큰 만료 확인 테스트 - 유효한 토큰")
    void isTokenExpired_ValidToken_ReturnsFalse() {
        // Given
        String email = "test@example.com";
        String name = "Test User";
        Set<String> roles = Set.of("USER");
        String token = rsaJwtService.generateAccessToken(email, name, roles);

        // When
        boolean isExpired = rsaJwtService.isTokenExpired(token);

        // Then
        assertThat(isExpired).isFalse();
    }

    @Test
    @DisplayName("토큰 타입 확인 테스트 - Access Token")
    void getTokenType_AccessToken_ReturnsAccess() {
        // Given
        String email = "test@example.com";
        String name = "Test User";
        Set<String> roles = Set.of("USER");
        String token = rsaJwtService.generateAccessToken(email, name, roles);

        // When
        String tokenType = rsaJwtService.getTokenType(token);

        // Then
        assertThat(tokenType).isEqualTo("access");
    }

    @Test
    @DisplayName("토큰 타입 확인 테스트 - Refresh Token")
    void getTokenType_RefreshToken_ReturnsRefresh() {
        // Given
        String email = "test@example.com";
        String token = rsaJwtService.generateRefreshToken(email);

        // When
        String tokenType = rsaJwtService.getTokenType(token);

        // Then
        assertThat(tokenType).isEqualTo("refresh");
    }

    @Test
    @DisplayName("공개 키 문자열 반환 테스트")
    void getPublicKeyAsString_ReturnsBase64String() {
        // When
        String publicKeyString = rsaJwtService.getPublicKeyAsString();

        // Then
        assertThat(publicKeyString).isNotNull();
        assertThat(publicKeyString).isNotEmpty();

        // Base64 문자열인지 확인
        assertThatCode(() -> java.util.Base64.getDecoder().decode(publicKeyString))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("PEM 형식 공개 키 반환 테스트")
    void getPublicKeyAsPem_ReturnsPemFormat() {
        // When
        String pemKey = rsaJwtService.getPublicKeyAsPem();

        // Then
        assertThat(pemKey).isNotNull();
        assertThat(pemKey).startsWith("-----BEGIN PUBLIC KEY-----");
        assertThat(pemKey).endsWith("-----END PUBLIC KEY-----");
        assertThat(pemKey).contains("\n");
    }

    @Test
    @DisplayName("RSA 서명 검증 테스트 - 다른 키로는 검증 실패")
    void tokenVerification_WithDifferentKey_Fails() throws NoSuchAlgorithmException {
        // Given
        String email = "test@example.com";
        String name = "Test User";
        Set<String> roles = Set.of("USER");
        String token = rsaJwtService.generateAccessToken(email, name, roles);

        // 다른 RSA 서비스 생성
        RsaJwtService anotherRsaService = new RsaJwtService();
        setField(anotherRsaService, "accessTokenExpiration", accessTokenExpiration);
        setField(anotherRsaService, "refreshTokenExpiration", refreshTokenExpiration);
        anotherRsaService.init();

        // When & Then
        // 다른 키로는 토큰 검증이 실패해야 함
        assertThat(anotherRsaService.isTokenValid(token)).isFalse();
    }
}