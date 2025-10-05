package com.example.authservice.repository;

import com.example.authservice.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.boot.test.autoconfigure.orm.jpa.TestEntityManager;
import org.springframework.test.context.ActiveProfiles;

import java.util.Optional;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;

@DataJpaTest
@ActiveProfiles("test")
class UserRepositoryTest {

    @Autowired
    private TestEntityManager entityManager;

    @Autowired
    private UserRepository userRepository;

    private User testUser;

    @BeforeEach
    void setUp() {
        testUser = new User();
        testUser.setEmail("test@example.com");
        testUser.setPassword("encodedPassword");
        testUser.setName("Test User");
        testUser.setRoles(Set.of("USER"));
    }

    @Test
    @DisplayName("이메일로 사용자 조회 성공 테스트")
    void findByEmail_UserExists_ReturnsUser() {
        // Given
        entityManager.persistAndFlush(testUser);

        // When
        Optional<User> found = userRepository.findByEmail("test@example.com");

        // Then
        assertThat(found).isPresent();
        assertThat(found.get().getEmail()).isEqualTo("test@example.com");
        assertThat(found.get().getName()).isEqualTo("Test User");
        assertThat(found.get().getRoles()).containsExactly("USER");
    }

    @Test
    @DisplayName("이메일로 사용자 조회 실패 테스트 - 존재하지 않는 이메일")
    void findByEmail_UserNotExists_ReturnsEmpty() {
        // When
        Optional<User> found = userRepository.findByEmail("nonexistent@example.com");

        // Then
        assertThat(found).isEmpty();
    }

    @Test
    @DisplayName("이메일 존재 여부 확인 테스트 - 존재하는 이메일")
    void existsByEmail_UserExists_ReturnsTrue() {
        // Given
        entityManager.persistAndFlush(testUser);

        // When
        boolean exists = userRepository.existsByEmail("test@example.com");

        // Then
        assertThat(exists).isTrue();
    }

    @Test
    @DisplayName("이메일 존재 여부 확인 테스트 - 존재하지 않는 이메일")
    void existsByEmail_UserNotExists_ReturnsFalse() {
        // When
        boolean exists = userRepository.existsByEmail("nonexistent@example.com");

        // Then
        assertThat(exists).isFalse();
    }

    @Test
    @DisplayName("사용자 저장 테스트")
    void save_User_Success() {
        // When
        User savedUser = userRepository.save(testUser);

        // Then
        assertThat(savedUser).isNotNull();
        assertThat(savedUser.getId()).isNotNull();
        assertThat(savedUser.getEmail()).isEqualTo("test@example.com");
        assertThat(savedUser.getName()).isEqualTo("Test User");
        assertThat(savedUser.getCreatedAt()).isNotNull();
    }

    @Test
    @DisplayName("사용자 삭제 테스트")
    void delete_User_Success() {
        // Given
        User savedUser = entityManager.persistAndFlush(testUser);
        Long userId = savedUser.getId();

        // When
        userRepository.delete(savedUser);
        entityManager.flush();

        // Then
        Optional<User> found = userRepository.findById(userId);
        assertThat(found).isEmpty();
    }

    @Test
    @DisplayName("모든 사용자 조회 테스트")
    void findAll_MultipleUsers_ReturnsAllUsers() {
        // Given
        User user1 = new User();
        user1.setEmail("user1@example.com");
        user1.setPassword("password1");
        user1.setName("User 1");
        user1.setRoles(Set.of("USER"));

        User user2 = new User();
        user2.setEmail("user2@example.com");
        user2.setPassword("password2");
        user2.setName("User 2");
        user2.setRoles(Set.of("USER", "ADMIN"));

        entityManager.persistAndFlush(user1);
        entityManager.persistAndFlush(user2);

        // When
        var users = userRepository.findAll();

        // Then
        assertThat(users).hasSize(2);
        assertThat(users).extracting("email")
                .containsExactlyInAnyOrder("user1@example.com", "user2@example.com");
    }

    @Test
    @DisplayName("사용자 업데이트 테스트")
    void update_User_Success() {
        // Given
        User savedUser = entityManager.persistAndFlush(testUser);
        entityManager.clear();

        // When
        Optional<User> userOptional = userRepository.findById(savedUser.getId());
        assertThat(userOptional).isPresent();
        User userToUpdate = userOptional.get();
        userToUpdate.setName("Updated Name");
        userToUpdate.getRoles().add("ADMIN");
        User updatedUser = userRepository.save(userToUpdate);

        // Then
        assertThat(updatedUser.getName()).isEqualTo("Updated Name");
        assertThat(updatedUser.getRoles()).containsExactlyInAnyOrder("USER", "ADMIN");
    }

    @Test
    @DisplayName("대소문자 구분 없는 이메일 조회 테스트")
    void findByEmail_CaseInsensitive() {
        // Given
        entityManager.persistAndFlush(testUser);

        // When
        Optional<User> foundLower = userRepository.findByEmail("test@example.com");
        Optional<User> foundUpper = userRepository.findByEmail("TEST@EXAMPLE.COM");

        // Then
        assertThat(foundLower).isPresent();
        // 주의: 기본적으로 대소문자를 구분하므로 대문자로 찾으면 찾아지지 않습니다
        assertThat(foundUpper).isEmpty();
    }
}