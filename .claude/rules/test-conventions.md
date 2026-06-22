# 테스트 규칙

이 파일은 테스트 작성 시 항상 따라야 할 규칙을 정의한다.

---

## 테스트 어노테이션 선택 기준

| 어노테이션 | 용도 | 특징 |
|-----------|------|------|
| `@SpringBootTest` | 통합 테스트 | 전체 컨텍스트 로딩 — 느림, 꼭 필요할 때만 |
| `@WebMvcTest` | Controller 단위 테스트 | Web 레이어만 로딩, Service는 Mock |
| `@DataJpaTest` | Repository 단위 테스트 | JPA 레이어만 로딩, H2 인메모리 DB 사용 |
| `@ExtendWith(MockitoExtension.class)` | Service 단위 테스트 | Spring 컨텍스트 없음, 가장 빠름 |

```java
// ✅ Service 단위 테스트 — MockitoExtension 사용
@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {
    @Mock
    private UserRepository userRepository;

    @InjectMocks
    private UserServiceImpl userService;
}

// ✅ Controller 단위 테스트 — @WebMvcTest 사용
@WebMvcTest(UserController.class)
class UserControllerTest {
    @Autowired
    private MockMvc mockMvc;

    @MockBean
    private UserService userService;
}

// ✅ Repository 단위 테스트 — @DataJpaTest 사용
@DataJpaTest
class UserRepositoryTest {
    @Autowired
    private UserRepository userRepository;
}

// ❌ 잘못된 예
@SpringBootTest                  // 단순 Service 테스트에 전체 컨텍스트 불필요
class UserServiceImplTest { }
```

---

## Mock 사용 규칙

| 어노테이션 | 사용 위치 | 설명 |
|-----------|----------|------|
| `@Mock` | `@ExtendWith(MockitoExtension.class)` | Spring 컨텍스트 없이 Mockito만 사용 |
| `@MockBean` | `@WebMvcTest`, `@SpringBootTest` | Spring 컨텍스트에 Mock 빈 등록 |

```java
// ✅ 올바른 예 — @ExtendWith에서 @Mock 사용
@ExtendWith(MockitoExtension.class)
class UserServiceImplTest {
    @Mock
    private UserRepository userRepository;
}

// ✅ 올바른 예 — @WebMvcTest에서 @MockBean 사용
@WebMvcTest(UserController.class)
class UserControllerTest {
    @MockBean
    private UserService userService;
}

// ❌ 잘못된 예
@WebMvcTest(UserController.class)
class UserControllerTest {
    @Mock                        // @WebMvcTest에서 @Mock은 Spring 빈으로 등록되지 않음
    private UserService userService;
}
```

---

## 테스트 메서드 네이밍

`메서드명_상황_기대결과` 형식으로 작성한다.

```java
// ✅ 올바른 예
@Test
void findById_존재하는_사용자_조회시_UserResponse_반환() { }

@Test
void findById_존재하지_않는_id_조회시_AuthException_발생() { }

@Test
void create_중복_이메일_입력시_DuplicateEmailException_발생() { }

// ❌ 잘못된 예
@Test
void testFindById() { }         // 상황과 기대결과 없음

@Test
void test1() { }                // 의미 없는 이름
```

---

## 테스트 구조 — given / when / then

모든 테스트는 `// given / when / then` 주석으로 단계를 구분한다.

```java
@Test
void findById_존재하는_사용자_조회시_UserResponse_반환() {
    // given
    User user = User.create("홍길동", "hong@example.com");
    given(userRepository.findById(1L)).willReturn(Optional.of(user));

    // when
    UserResponse response = userService.findById(1L);

    // then
    assertThat(response.name()).isEqualTo("홍길동");
    assertThat(response.email()).isEqualTo("hong@example.com");
}

@Test
void findById_존재하지_않는_id_조회시_AuthException_발생() {
    // given
    given(userRepository.findById(99L)).willReturn(Optional.empty());

    // when & then
    assertThatThrownBy(() -> userService.findById(99L))
            .isInstanceOf(AuthException.class);
}
```

---

## AssertJ 사용 규칙

JUnit `assertEquals` 대신 AssertJ `assertThat`을 사용한다.

```java
// ✅ 올바른 예
assertThat(response.name()).isEqualTo("홍길동");
assertThat(users).hasSize(3);
assertThat(user.getStatus()).isEqualTo(UserStatus.ACTIVE);
assertThatThrownBy(() -> userService.findById(99L))
        .isInstanceOf(AuthException.class);

// ❌ 잘못된 예
assertEquals("홍길동", response.name());       // JUnit assertEquals 사용 금지
assertTrue(users.size() == 3);                 // assertTrue 직접 비교 금지
```

---

## Controller 테스트

`@WebMvcTest` + `MockMvc`로 HTTP 요청/응답을 검증한다.
Security 필터가 개입하지 않도록 `@WithMockUser`를 사용한다.

```java
@WebMvcTest(UserController.class)
class UserControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockBean
    private UserService userService;

    @Test
    @WithMockUser
    void getUser_존재하는_사용자_조회시_200_반환() throws Exception {
        // given
        UserResponse response = new UserResponse(1L, "홍길동", "hong@example.com",
                UserStatus.ACTIVE, LocalDateTime.now());
        given(userService.findById(1L)).willReturn(response);

        // when & then
        mockMvc.perform(get("/api/v1/users/1"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.data.name").value("홍길동"))
                .andExpect(jsonPath("$.data.email").value("hong@example.com"));
    }

    @Test
    @WithMockUser
    void createUser_유효하지_않은_이메일_입력시_400_반환() throws Exception {
        // given
        CreateUserRequest request = new CreateUserRequest("홍길동", "invalid-email");

        // when & then
        mockMvc.perform(post("/api/v1/users")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(request)))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("C001"));
    }
}
```

---

## Repository 테스트

`@DataJpaTest`는 H2 인메모리 DB를 사용한다.
테스트 데이터는 `@BeforeEach`에서 직접 `save`로 준비한다.

```java
@DataJpaTest
class UserRepositoryTest {

    @Autowired
    private UserRepository userRepository;

    @BeforeEach
    void setUp() {
        userRepository.save(User.create("홍길동", "hong@example.com"));
    }

    @Test
    void existsByEmail_이미_존재하는_이메일이면_true_반환() {
        assertThat(userRepository.existsByEmail("hong@example.com")).isTrue();
    }

    @Test
    void existsByEmail_존재하지_않는_이메일이면_false_반환() {
        assertThat(userRepository.existsByEmail("none@example.com")).isFalse();
    }
}
```

---

## 테스트 클래스 패키지 위치

테스트 클래스는 대상 클래스와 **동일한 패키지**에 위치시킨다.

```
src/main/java/com/auth/user/application/UserServiceImpl.java
src/test/java/com/auth/user/application/UserServiceImplTest.java  ✅

src/test/java/com/auth/UserServiceImplTest.java                   ❌
```

---

## TestContainers 통합 테스트

PostgreSQL, Redis 등 외부 인프라가 필요한 통합 테스트는 TestContainers를 사용한다.
`ContainersConfig`에 컨테이너 설정을 모아 두고, `LocalApplication`으로 로컬 환경을 구동한다.

```java
// ✅ 테스트용 컨테이너 설정 — ContainersConfig.java
@TestConfiguration(proxyBeanMethods = false)
public class ContainersConfig {

    @Bean
    @ServiceConnection
    PostgreSQLContainer<?> postgresContainer() {
        return new PostgreSQLContainer<>("postgres:16");
    }

    @Bean
    @ServiceConnection
    RedisContainer redisContainer() {
        return new RedisContainer("redis:7");
    }
}

// ✅ 통합 테스트에서 ContainersConfig 임포트
@SpringBootTest
@Import(ContainersConfig.class)
class UserIntegrationTest {
    @Autowired
    private UserService userService;
}
```

`@ServiceConnection`을 사용하면 컨테이너 포트를 수동으로 바인딩하지 않아도 된다.
단순 Service 단위 테스트에는 TestContainers를 사용하지 않는다.
