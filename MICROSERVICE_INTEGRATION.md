# 마이크로서비스 JWT 토큰 검증 가이드

다른 마이크로서비스에서 이 인증 서비스에서 발급한 JWT 토큰을 **독립적으로** 검증하는 방법을 설명합니다.

## RSA 공개 키를 사용한 분산 토큰 검증

### 장점
- ✅ **SPOF 없음**: 인증 서비스가 다운되어도 다른 서비스들이 토큰 검증 가능
- ✅ **성능 우수**: 네트워크 호출 없이 로컬에서 즉시 검증
- ✅ **보안**: RSA 공개/비공개 키 방식으로 안전한 토큰 검증
- ✅ **확장성**: 새로운 서비스 추가 시 공개 키만 가져오면 됨

## 공개 키 엔드포인트

### 인증 서비스에서 제공하는 엔드포인트
- **GET** `/.well-known/public-key`: Base64 인코딩된 공개 키
- **GET** `/.well-known/public-key.pem`: PEM 형식의 공개 키
- **GET** `/.well-known/jwks.json`: JWKS 표준 형식

## 방법 1: JwtValidator 유틸리티 사용 (권장)

### 1단계: 의존성 추가
```gradle
// build.gradle
implementation 'io.jsonwebtoken:jjwt-api:0.12.3'
runtimeOnly 'io.jsonwebtoken:jjwt-impl:0.12.3'
runtimeOnly 'io.jsonwebtoken:jjwt-jackson:0.12.3'
implementation 'org.springframework:spring-web' // RestTemplate용
```

### 2단계: JwtValidator 클래스 복사
JwtValidator.java 파일을 다른 서비스의 util 패키지에 복사합니다.

### 3단계: 토큰 검증 서비스 구현
```java
@Service
public class TokenService {

    private final JwtValidator jwtValidator;

    public TokenService() {
        // 방법 1: 런타임에 공개 키 가져오기
        this.jwtValidator = new JwtValidator("http://auth-service:8080");

        // 방법 2: PEM 키 직접 사용 (더 빠름)
        // String pemKey = "-----BEGIN PUBLIC KEY-----\n...";
        // this.jwtValidator = JwtValidator.fromPemKey(pemKey);
    }

    public boolean isValidToken(String token) {
        JwtValidator.TokenInfo tokenInfo = jwtValidator.validateToken(token);
        return tokenInfo.isValid() && tokenInfo.isAccessToken();
    }

    public String getUserEmail(String token) {
        JwtValidator.TokenInfo tokenInfo = jwtValidator.validateToken(token);
        return tokenInfo.isValid() ? tokenInfo.getEmail() : null;
    }

    public boolean hasRole(String token, String role) {
        JwtValidator.TokenInfo tokenInfo = jwtValidator.validateToken(token);
        return tokenInfo.isValid() && tokenInfo.hasRole(role);
    }

    public boolean hasAnyRole(String token, String... roles) {
        JwtValidator.TokenInfo tokenInfo = jwtValidator.validateToken(token);
        return tokenInfo.isValid() && tokenInfo.hasAnyRole(roles);
    }
}
```

## 방법 2: Spring Security 필터 통합

### Spring Security 설정
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter() {
        return new JwtAuthenticationFilter();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/public/**").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .addFilterBefore(jwtAuthenticationFilter(),
                UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
```

### JWT 인증 필터
```java
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtValidator jwtValidator;

    public JwtAuthenticationFilter() {
        this.jwtValidator = new JwtValidator("http://auth-service:8080");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain filterChain) throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);
            JwtValidator.TokenInfo tokenInfo = jwtValidator.validateToken(token);

            if (tokenInfo.isValid() && tokenInfo.isAccessToken()) {
                // Spring Security Context에 인증 정보 설정
                List<SimpleGrantedAuthority> authorities = tokenInfo.getRoles().stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .collect(Collectors.toList());

                UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(
                        tokenInfo.getEmail(), null, authorities);

                SecurityContextHolder.getContext().setAuthentication(authentication);
            }
        }

        filterChain.doFilter(request, response);
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        return path.startsWith("/public/") || path.startsWith("/actuator/");
    }
}
```

## 방법 3: 컨트롤러에서 직접 사용

```java
@RestController
@RequestMapping("/api/users")
public class UserController {

    private final JwtValidator jwtValidator = new JwtValidator("http://auth-service:8080");

    @GetMapping("/profile")
    public ResponseEntity<UserProfile> getProfile(
            @RequestHeader("Authorization") String authHeader) {

        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        String token = authHeader.substring(7);
        JwtValidator.TokenInfo tokenInfo = jwtValidator.validateToken(token);

        if (!tokenInfo.isValid()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        // 사용자 정보로 프로필 조회
        UserProfile profile = userService.getProfile(tokenInfo.getEmail());
        return ResponseEntity.ok(profile);
    }

    @DeleteMapping("/{userId}")
    public ResponseEntity<Void> deleteUser(
            @PathVariable Long userId,
            @RequestHeader("Authorization") String authHeader) {

        String token = authHeader.substring(7);
        JwtValidator.TokenInfo tokenInfo = jwtValidator.validateToken(token);

        // 관리자 권한 확인
        if (!tokenInfo.isValid() || !tokenInfo.hasRole("ADMIN")) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }

        userService.deleteUser(userId);
        return ResponseEntity.ok().build();
    }
}
```

## Docker Compose 설정

```yaml
version: '3.8'
services:
  auth-service:
    image: auth-service:latest
    ports:
      - "8080:8080"
    environment:
      - SPRING_DATASOURCE_URL=jdbc:mysql://mysql:3306/authdb

  user-service:
    image: user-service:latest
    ports:
      - "8081:8081"
    environment:
      - AUTH_SERVICE_URL=http://auth-service:8080
    depends_on:
      - auth-service

  product-service:
    image: product-service:latest
    ports:
      - "8082:8082"
    environment:
      - AUTH_SERVICE_URL=http://auth-service:8080
    depends_on:
      - auth-service
```

## Kubernetes 설정

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: microservice-config
data:
  AUTH_SERVICE_URL: "http://auth-service.default.svc.cluster.local:8080"
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: user-service
spec:
  replicas: 3
  selector:
    matchLabels:
      app: user-service
  template:
    metadata:
      labels:
        app: user-service
    spec:
      containers:
      - name: user-service
        image: user-service:latest
        envFrom:
        - configMapRef:
            name: microservice-config
```

## 성능 최적화 팁

### 1. 공개 키 캐싱
```java
@Component
public class PublicKeyCache {

    private String cachedPublicKey;
    private LocalDateTime lastUpdated;
    private final Duration cacheExpiry = Duration.ofHours(1);

    public String getPublicKey(String authServiceUrl) {
        if (cachedPublicKey == null ||
            lastUpdated.plus(cacheExpiry).isBefore(LocalDateTime.now())) {

            refreshPublicKey(authServiceUrl);
        }
        return cachedPublicKey;
    }

    private void refreshPublicKey(String authServiceUrl) {
        // 공개 키 갱신 로직
        RestTemplate restTemplate = new RestTemplate();
        this.cachedPublicKey = restTemplate.getForObject(
            authServiceUrl + "/.well-known/public-key", String.class);
        this.lastUpdated = LocalDateTime.now();
    }
}
```

### 2. 토큰 검증 결과 캐싱 (주의: 보안 고려)
```java
@Service
public class TokenCacheService {

    private final Cache<String, TokenInfo> tokenCache =
        Caffeine.newBuilder()
            .maximumSize(1000)
            .expireAfterWrite(2, TimeUnit.MINUTES) // 짧은 캐시
            .build();

    public TokenInfo getTokenInfo(String token) {
        return tokenCache.get(token, this::validateToken);
    }

    private TokenInfo validateToken(String token) {
        return jwtValidator.validateToken(token);
    }
}
```

## 보안 고려사항

### 1. HTTPS 사용
- 공개 키는 반드시 HTTPS를 통해서만 가져오세요
- 프로덕션 환경에서는 모든 서비스 간 통신을 TLS로 암호화

### 2. 키 로테이션 대응
```java
@Scheduled(fixedRate = 3600000) // 1시간마다
public void refreshPublicKey() {
    try {
        jwtValidator.refreshPublicKey();
    } catch (Exception e) {
        log.warn("공개 키 갱신 실패: {}", e.getMessage());
    }
}
```

### 3. 토큰 타입 검증
```java
// Refresh Token으로 API 접근 방지
if (!tokenInfo.isAccessToken()) {
    return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
}
```

### 4. 적절한 권한 검증
```java
// 세밀한 권한 제어
if (!tokenInfo.hasAllRoles("USER", "PREMIUM")) {
    return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
}
```

## 장애 대응 전략

### 1. Circuit Breaker 패턴
```java
@Component
public class ResilientJwtValidator {

    @CircuitBreaker(name = "auth-service")
    @Retry(name = "auth-service")
    public String getPublicKey(String authServiceUrl) {
        return restTemplate.getForObject(
            authServiceUrl + "/.well-known/public-key", String.class);
    }
}
```

### 2. Fallback 메커니즘
```java
// 공개 키를 가져올 수 없을 때 환경변수에서 로드
@Value("${jwt.fallback-public-key:}")
private String fallbackPublicKey;
```

이제 각 마이크로서비스가 **독립적으로** JWT 토큰을 검증할 수 있어 단일 실패 지점 문제가 해결되었습니다!