package com.example.authservice.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.Setter;

import java.util.List;
import java.util.Map;

@Getter
@Setter
@AllArgsConstructor
public class JwksResponse {
    private List<Map<String, Object>> keys;

    public static JwksResponse create(String publicKey, String keyId) {
        Map<String, Object> key = Map.of(
                "kty", "RSA",
                "use", "sig",
                "kid", keyId,
                "key", publicKey,
                "alg", "RS256"
        );

        return new JwksResponse(List.of(key));
    }
}