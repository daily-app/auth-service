package com.example.authservice.controller;

import com.example.authservice.dto.JwksResponse;
import com.example.authservice.service.RsaJwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/.well-known")
@RequiredArgsConstructor
public class JwksController {

    private final RsaJwtService rsaJwtService;

    @GetMapping("/jwks.json")
    public ResponseEntity<JwksResponse> getJwks() {
        String publicKey = rsaJwtService.getPublicKeyAsString();
        JwksResponse jwks = JwksResponse.create(publicKey, "auth-service-key-1");
        return ResponseEntity.ok(jwks);
    }

    @GetMapping("/public-key")
    public ResponseEntity<String> getPublicKey() {
        return ResponseEntity.ok(rsaJwtService.getPublicKeyAsString());
    }

    @GetMapping("/public-key.pem")
    public ResponseEntity<String> getPublicKeyPem() {
        return ResponseEntity.ok(rsaJwtService.getPublicKeyAsPem());
    }
}