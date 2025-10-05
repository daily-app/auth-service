package com.example.authservice.service;

import com.example.authservice.dto.AuthResponse;
import com.example.authservice.dto.LoginRequest;
import com.example.authservice.dto.RegisterRequest;
import com.example.authservice.entity.User;
import com.example.authservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Service
@RequiredArgsConstructor
@Transactional
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RsaJwtService jwtService;

    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("이미 존재하는 이메일입니다");
        }

        User user = new User();
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setName(request.getName());
        user.setRoles(Set.of("USER"));

        User savedUser = userRepository.save(user);

        String accessToken = jwtService.generateAccessToken(savedUser.getEmail(), savedUser.getRoles());
        String refreshToken = jwtService.generateRefreshToken(savedUser.getEmail());

        return new AuthResponse(
                accessToken,
                refreshToken,
                savedUser.getEmail(),
                savedUser.getName(),
                savedUser.getRoles()
        );
    }

    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("존재하지 않는 사용자입니다"));

        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new RuntimeException("비밀번호가 일치하지 않습니다");
        }

        String accessToken = jwtService.generateAccessToken(user.getEmail(), user.getRoles());
        String refreshToken = jwtService.generateRefreshToken(user.getEmail());

        return new AuthResponse(
                accessToken,
                refreshToken,
                user.getEmail(),
                user.getName(),
                user.getRoles()
        );
    }

    public AuthResponse refreshToken(String refreshToken) {
        if (!jwtService.isTokenValid(refreshToken) || jwtService.isTokenExpired(refreshToken)) {
            throw new RuntimeException("유효하지 않은 리프레시 토큰입니다");
        }

        if (!"refresh".equals(jwtService.getTokenType(refreshToken))) {
            throw new RuntimeException("리프레시 토큰이 아닙니다");
        }

        String email = jwtService.extractEmail(refreshToken);
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("존재하지 않는 사용자입니다"));

        String newAccessToken = jwtService.generateAccessToken(user.getEmail(), user.getRoles());
        String newRefreshToken = jwtService.generateRefreshToken(user.getEmail());

        return new AuthResponse(
                newAccessToken,
                newRefreshToken,
                user.getEmail(),
                user.getName(),
                user.getRoles()
        );
    }
}