# 서비스 테스트 설계

이 파일은 각 서비스 클래스의 테스트 케이스 목록과 Mock 구성을 정의한다.
구현 전 이 파일을 먼저 확인하고, 구현 후 체크박스를 체크한다.

---

## UserServiceTest

**위치**: `src/test/java/com/auth/user/application/UserServiceTest.java`
**어노테이션**: `@ExtendWith(MockitoExtension.class)`

### Mock 구성

```java
@Mock UserRepository userRepository;
@Mock RoleRepository roleRepository;
@Mock PasswordEncoder passwordEncoder;
@InjectMocks UserService userService;
```

### 테스트 케이스

- [ ] `signUp_중복_이메일_입력시_EMAIL_ALREADY_EXISTS_예외_발생`
- [ ] `signUp_유효한_요청_입력시_UserResponse_반환`
- [ ] `getMe_존재하는_userId_조회시_UserResponse_반환`
- [ ] `getMe_존재하지_않는_userId_조회시_USER_NOT_FOUND_예외_발생`
- [ ] `updateNickname_존재하는_userId_입력시_닉네임_업데이트된_UserResponse_반환`
- [ ] `updateNickname_존재하지_않는_userId_입력시_USER_NOT_FOUND_예외_발생`
- [ ] `withdraw_존재하는_userId_입력시_WITHDRAWN_상태로_변경`
- [ ] `withdraw_존재하지_않는_userId_입력시_USER_NOT_FOUND_예외_발생`

### 핵심 검증 포인트

```java
// signUp — Role 부여 확인
given(roleRepository.findByName("ROLE_USER")).willReturn(Optional.of(userRole));
// user.addRole 호출 여부는 User 객체 상태로 검증 (verify 대신 assertThat)

// withdraw — 상태 변경 메서드 호출 확인
// User는 상태 변경 메서드만 있고 getter로 확인
// → spy 또는 실제 User 객체를 생성해 상태 검증
User user = User.builder().email(...).password(...).nickname(...).build();
given(userRepository.findById(userId)).willReturn(Optional.of(user));
userService.withdraw(userId);
assertThat(user.getStatus()).isEqualTo(UserStatus.WITHDRAWN);
```

---

## LoginAttemptServiceTest

**위치**: `src/test/java/com/auth/security/application/LoginAttemptServiceTest.java`
**어노테이션**: `@ExtendWith(MockitoExtension.class)`

### Mock 구성

```java
@Mock StringRedisTemplate redisTemplate;
@InjectMocks LoginAttemptService loginAttemptService;
```

### 테스트 케이스

- [ ] `recordFailure_이메일과_IP에_실패_횟수_증가`
- [ ] `recordFailure_Redis_장애시_예외_미전파`
- [ ] `clearFailures_이메일과_IP_키_삭제`
- [ ] `clearFailures_Redis_장애시_예외_미전파`
- [ ] `isEmailBlocked_5회_미만이면_false_반환`
- [ ] `isEmailBlocked_5회_이상이면_true_반환`
- [ ] `isEmailBlocked_Redis_장애시_false_반환`
- [ ] `isIpBlocked_5회_미만이면_false_반환`
- [ ] `isIpBlocked_5회_이상이면_true_반환`
- [ ] `isIpBlocked_Redis_장애시_false_반환`

### 핵심 검증 포인트

```java
// isBlocked — ValueOperations 체이닝 모킹
ValueOperations<String, String> valueOps = mock(ValueOperations.class);
given(redisTemplate.opsForValue()).willReturn(valueOps);
given(valueOps.get("login:fail:email:test@example.com")).willReturn("5");

// Redis 장애 — fail-open 검증
given(redisTemplate.opsForValue()).willThrow(new RuntimeException("Redis down"));
assertThat(loginAttemptService.isEmailBlocked("test@example.com")).isFalse();

// recordFailure — execute 호출 횟수 검증 (email 키 + ip 키 = 2회)
verify(redisTemplate, times(2)).execute(any(RedisScript.class), anyList(), any());
```

---

## CustomUserDetailsServiceTest

**위치**: `src/test/java/com/auth/security/application/CustomUserDetailsServiceTest.java`
**어노테이션**: `@ExtendWith(MockitoExtension.class)`

### Mock 구성

```java
@Mock UserRepository userRepository;
@Mock LoginAttemptService loginAttemptService;
@InjectMocks CustomUserDetailsService userDetailsService;
```

### 테스트 케이스

- [ ] `loadUserByUsername_차단된_이메일이면_LockedException_발생`
- [ ] `loadUserByUsername_존재하지_않는_이메일이면_UsernameNotFoundException_발생`
- [ ] `loadUserByUsername_SUSPENDED_상태이면_isEnabled_false_반환`
- [ ] `loadUserByUsername_WITHDRAWN_상태이면_isAccountNonExpired_false_반환`
- [ ] `loadUserByUsername_정상_사용자이면_authorities_포함된_UserDetails_반환`

### 핵심 검증 포인트

```java
// UserDetails 상태 플래그 매핑 확인
// SUSPENDED  → isEnabled() == false
// WITHDRAWN  → isAccountNonExpired() == false
// ACTIVE     → 모든 플래그 true

// authorities 검증
assertThat(userDetails.getAuthorities())
        .extracting(GrantedAuthority::getAuthority)
        .containsExactly("ROLE_USER");

// principal이 userId(UUID)인지 확인
assertThat(userDetails.getUsername()).isEqualTo(user.getId().toString());
```

---

## SimpleClientManagementTest

**위치**: `src/test/java/com/auth/client/application/SimpleClientManagementTest.java`
**어노테이션**: `@ExtendWith(MockitoExtension.class)`

### Mock 구성

```java
@Mock RegisteredClientRepository registeredClientRepository;
@Mock ClientRepository clientRepository;
@Mock PasswordEncoder passwordEncoder;
@InjectMocks SimpleClientManagement clientManagement;
```

### 테스트 케이스

- [ ] `findAll_클라이언트_목록_반환`
- [ ] `getDetail_존재하는_id_조회시_ClientDetail_반환`
- [ ] `getDetail_존재하지_않는_id_조회시_CLIENT_NOT_FOUND_예외_발생`
- [ ] `create_중복_clientId_입력시_CLIENT_ID_ALREADY_EXISTS_예외_발생`
- [ ] `create_유효한_요청_입력시_SecretRevealResponse_반환`
- [ ] `update_존재하지_않는_id_입력시_CLIENT_NOT_FOUND_예외_발생`
- [ ] `update_유효한_요청_입력시_변경된_클라이언트_저장`
- [ ] `delete_존재하지_않는_id_입력시_CLIENT_NOT_FOUND_예외_발생`
- [ ] `delete_존재하는_id_입력시_deleteById_호출`
- [ ] `regenerateSecret_존재하지_않는_id_입력시_CLIENT_NOT_FOUND_예외_발생`
- [ ] `regenerateSecret_존재하는_id_입력시_새_시크릿_반환`

### 핵심 검증 포인트

```java
// RegisteredClient 테스트 픽스처 생성
RegisteredClient fixture = RegisteredClient.withId(UUID.randomUUID().toString())
        .clientId("test-client")
        .clientSecret("encoded-secret")
        .clientName("Test Client")
        .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
        .redirectUri("https://example.com/callback")
        .scope("openid")
        .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
        .clientSettings(ClientSettings.builder()
                .setting("loginPageUri", "https://example.com/login")
                .build())
        .tokenSettings(TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofMinutes(30))
                .refreshTokenTimeToLive(Duration.ofDays(7))
                .build())
        .build();

// create — rawSecret이 인코딩되어 저장되는지 확인
given(passwordEncoder.encode(anyString())).willReturn("encoded");
SecretRevealResponse response = clientManagement.create(request);
assertThat(response.rawSecret()).isNotBlank();          // 원문 반환
verify(passwordEncoder).encode(response.rawSecret());  // 인코딩 후 저장

// regenerateSecret — 기존 시크릿과 다른 새 시크릿 반환 확인
assertThat(response.rawSecret()).isNotEqualTo("old-secret");
verify(registeredClientRepository).save(any(RegisteredClient.class));
```

---

## 진행 상태

| 테스트 클래스 | 전체 | 완료 |
|---|---|---|
| UserServiceTest | 8 | 0 |
| LoginAttemptServiceTest | 10 | 0 |
| CustomUserDetailsServiceTest | 5 | 0 |
| SimpleClientManagementTest | 11 | 0 |
| **합계** | **34** | **0** |
