package com.example.authservice.controller;

import com.example.authservice.service.RsaJwtService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class JwksControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private RsaJwtService rsaJwtService;

    @Test
    @DisplayName("JWKS 엔드포인트 테스트")
    void getJwks_ReturnsJwksResponse() throws Exception {
        // Given
        String mockPublicKey = "mockPublicKeyString";
        when(rsaJwtService.getPublicKeyAsString()).thenReturn(mockPublicKey);

        // When & Then
        mockMvc.perform(get("/.well-known/jwks.json"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys").isArray())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andExpect(jsonPath("$.keys[0].kid").value("auth-service-key-1"))
                .andExpect(jsonPath("$.keys[0].key").value(mockPublicKey))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"));
    }

    @Test
    @DisplayName("공개 키 엔드포인트 테스트")
    void getPublicKey_ReturnsPublicKeyString() throws Exception {
        // Given
        String mockPublicKey = "mockPublicKeyString";
        when(rsaJwtService.getPublicKeyAsString()).thenReturn(mockPublicKey);

        // When & Then
        mockMvc.perform(get("/.well-known/public-key"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string(mockPublicKey));
    }

    @Test
    @DisplayName("PEM 형식 공개 키 엔드포인트 테스트")
    void getPublicKeyPem_ReturnsPemFormat() throws Exception {
        // Given
        String mockPemKey = "-----BEGIN PUBLIC KEY-----\nMockPemKeyContent\n-----END PUBLIC KEY-----";
        when(rsaJwtService.getPublicKeyAsPem()).thenReturn(mockPemKey);

        // When & Then
        mockMvc.perform(get("/.well-known/public-key.pem"))
                .andDo(print())
                .andExpect(status().isOk())
                .andExpect(content().string(mockPemKey));
    }
}