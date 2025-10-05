package com.example.authservice.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import org.springframework.web.client.RestTemplate;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.Set;

/**
 * 다른 마이크로서비스에서 JWT 토큰을 검증하기 위한 유틸리티 클래스
 *
 * 사용법:
 * 1. 인증 서비스에서 공개 키를 가져와서 초기화
 * 2. validateToken 메서드로 토큰 검증
 *
 * 예시:
 * JwtValidator validator = new JwtValidator("http://auth-service:8080");
 * JwtValidator.TokenInfo tokenInfo = validator.validateToken(token);
 * if (tokenInfo.isValid()) {
 *     String email = tokenInfo.getEmail();
 *     Set<String> roles = tokenInfo.getRoles();
 * }
 */
public class JwtValidator {

    private final String authServiceUrl;
    private final RestTemplate restTemplate;
    private PublicKey publicKey;

    public JwtValidator(String authServiceUrl) {
        this.authServiceUrl = authServiceUrl;
        this.restTemplate = new RestTemplate();
        loadPublicKey();
    }

    /**
     * 인증 서비스에서 공개 키를 가져와서 로드
     */
    private void loadPublicKey() {
        try {
            String publicKeyString = restTemplate.getForObject(
                authServiceUrl + "/.well-known/public-key",
                String.class
            );

            if (publicKeyString != null) {
                byte[] keyBytes = Base64.getDecoder().decode(publicKeyString);
                X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
                KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                this.publicKey = keyFactory.generatePublic(keySpec);
            }
        } catch (Exception e) {
            throw new RuntimeException("공개 키를 로드할 수 없습니다: " + e.getMessage(), e);
        }
    }

    /**
     * PEM 형식의 공개 키를 사용하여 초기화 (네트워크 호출 없이 사용 가능)
     */
    public static JwtValidator fromPemKey(String pemKey) {
        JwtValidator validator = new JwtValidator("");
        validator.loadPublicKeyFromPem(pemKey);
        return validator;
    }

    private void loadPublicKeyFromPem(String pemKey) {
        try {
            // PEM 헤더/푸터 제거 및 개행 문자 제거
            String publicKeyPEM = pemKey
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s", "");

            byte[] keyBytes = Base64.getDecoder().decode(publicKeyPEM);
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            this.publicKey = keyFactory.generatePublic(keySpec);
        } catch (Exception e) {
            throw new RuntimeException("PEM 공개 키를 로드할 수 없습니다: " + e.getMessage(), e);
        }
    }

    /**
     * JWT 토큰을 검증하고 정보를 반환
     */
    public TokenInfo validateToken(String token) {
        try {
            if (publicKey == null) {
                return TokenInfo.invalid("공개 키가 로드되지 않았습니다");
            }

            Claims claims = Jwts.parser()
                    .verifyWith(publicKey)
                    .build()
                    .parseSignedClaims(token)
                    .getPayload();

            // 만료 시간 확인
            if (claims.getExpiration().before(new Date())) {
                return TokenInfo.invalid("토큰이 만료되었습니다");
            }

            String email = claims.getSubject();
            String tokenType = (String) claims.get("type");

            @SuppressWarnings("unchecked")
            Set<String> roles = (Set<String>) claims.get("roles");

            return TokenInfo.valid(email, roles, tokenType, claims.getExpiration().getTime());

        } catch (JwtException e) {
            return TokenInfo.invalid("유효하지 않은 토큰입니다: " + e.getMessage());
        } catch (Exception e) {
            return TokenInfo.invalid("토큰 검증 중 오류가 발생했습니다: " + e.getMessage());
        }
    }

    /**
     * 공개 키를 수동으로 새로고침 (키 로테이션 시 사용)
     */
    public void refreshPublicKey() {
        loadPublicKey();
    }

    /**
     * 토큰 검증 결과를 담는 클래스
     */
    public static class TokenInfo {
        private final boolean valid;
        private final String email;
        private final Set<String> roles;
        private final String tokenType;
        private final Long expiresAt;
        private final String errorMessage;

        private TokenInfo(boolean valid, String email, Set<String> roles, String tokenType, Long expiresAt, String errorMessage) {
            this.valid = valid;
            this.email = email;
            this.roles = roles;
            this.tokenType = tokenType;
            this.expiresAt = expiresAt;
            this.errorMessage = errorMessage;
        }

        public static TokenInfo valid(String email, Set<String> roles, String tokenType, Long expiresAt) {
            return new TokenInfo(true, email, roles, tokenType, expiresAt, null);
        }

        public static TokenInfo invalid(String errorMessage) {
            return new TokenInfo(false, null, null, null, null, errorMessage);
        }

        // Getters
        public boolean isValid() { return valid; }
        public String getEmail() { return email; }
        public Set<String> getRoles() { return roles; }
        public String getTokenType() { return tokenType; }
        public Long getExpiresAt() { return expiresAt; }
        public String getErrorMessage() { return errorMessage; }

        /**
         * 특정 역할을 가지고 있는지 확인
         */
        public boolean hasRole(String role) {
            return roles != null && roles.contains(role);
        }

        /**
         * 여러 역할 중 하나라도 가지고 있는지 확인
         */
        public boolean hasAnyRole(String... requiredRoles) {
            if (roles == null) return false;
            for (String role : requiredRoles) {
                if (roles.contains(role)) {
                    return true;
                }
            }
            return false;
        }

        /**
         * 모든 역할을 가지고 있는지 확인
         */
        public boolean hasAllRoles(String... requiredRoles) {
            if (roles == null) return false;
            for (String role : requiredRoles) {
                if (!roles.contains(role)) {
                    return false;
                }
            }
            return true;
        }

        /**
         * Access Token인지 확인
         */
        public boolean isAccessToken() {
            return "access".equals(tokenType);
        }

        /**
         * Refresh Token인지 확인
         */
        public boolean isRefreshToken() {
            return "refresh".equals(tokenType);
        }
    }
}