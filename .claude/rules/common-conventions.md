# 공통 컨벤션 규칙

모든 레이어에서 공통으로 적용되는 규칙을 정의한다.

---

## Lombok

| 어노테이션 | 사용 | 비고 |
|-----------|------|------|
| `@RequiredArgsConstructor` | ✅ 항상 사용 | DI는 `final` 필드 + 이 어노테이션으로 처리 |
| `@Getter` | ✅ 허용 | Entity, DTO 외 클래스에 사용 |
| `@Slf4j` | ✅ 허용 | 로그가 필요한 클래스에 선언 |
| `@Data` | ❌ 금지 | `@Setter` 포함으로 Entity 불변성 파괴 |
| `@Setter` | ❌ 금지 | 상태 변경은 의미 있는 메서드로 표현 |
| `@Builder` | ⚠️ 제한 | `private` 생성자에만 적용, Entity 외부 빌더 노출 금지 |

```java
// ✅ 올바른 예
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;
}

// ❌ 잘못된 예
@Data                        // @Setter 포함 — Entity에 사용 금지
public class User { ... }

@Autowired                   // 필드 주입 금지
private UserService userService;
```

---

## 유틸리티 클래스

인스턴스화가 불필요한 유틸리티 클래스는 `private` 생성자를 선언한다.

```java
// ✅ 올바른 예
public final class HttpUtils {
    private HttpUtils() {}

    public static String getClientIp(HttpServletRequest request) { ... }
}

// ❌ 잘못된 예
public class HttpUtils {                   // final 없음
    public static String getClientIp() {} // 생성자 미차단
}
```

---

## 상수

매직 넘버·문자열은 상수로 선언한다.
상수는 해당 클래스 내부에 `private static final`로 선언하거나, 여러 클래스에서 공유할 경우 별도 상수 클래스를 만든다.

```java
// ✅ 올바른 예
private static final String EMAIL_VERIFY_KEY_PREFIX = "email:verify:";
private static final int MAX_RETRY_COUNT = 5;

// ❌ 잘못된 예
redisTemplate.opsForValue().set("email:verify:" + token, email);  // 매직 문자열
```

---

## 트랜잭션 경계

Service 클래스에 `@Transactional`을 클래스 레벨로 선언하고, 조회 메서드는 `@Transactional(readOnly = true)`를 메서드 레벨에 추가한다.
`readOnly = true`는 JPA 더티 체킹 비활성화 + 읽기 전용 커넥션 힌트를 제공한다.

```java
// ✅ 올바른 예
@Service
@Transactional          // 기본값: 쓰기 트랜잭션
@RequiredArgsConstructor
public class UserService {

    @Transactional(readOnly = true)   // 조회는 명시적으로 오버라이드
    public UserResponse getMe(UUID id) { ... }

    public UserResponse signUp(SignUpRequest request) { ... }   // 클래스 레벨 상속
}

// ❌ 잘못된 예
public class UserService {
    // 트랜잭션 없음 — 조회와 쓰기 구분 불가
    public UserResponse getMe(UUID id) { ... }
}
```

---

## Entity 상태 변경 메서드

Entity의 상태 변경은 의미 있는 메서드로 표현한다. 필드에 직접 접근하거나 `@Setter`를 통해 상태를 변경하지 않는다.

```java
// ✅ 올바른 예
public class User {
    private UserStatus status;

    public void suspend() { this.status = UserStatus.SUSPENDED; }
    public void withdraw() { this.status = UserStatus.WITHDRAWN; }
}

// 호출부
user.suspend();

// ❌ 잘못된 예
user.setStatus(UserStatus.SUSPENDED);   // @Setter 사용 금지
user.status = UserStatus.SUSPENDED;     // 필드 직접 접근 금지
```

---

## DTO — Record vs Class 선택 기준

| 상황 | 선택 | 이유 |
|------|------|------|
| 일반 Request / Response DTO | `record` | 불변, 간결한 선언 |
| Spring MVC가 직접 바인딩하는 폼 DTO (`@ModelAttribute`) | `class` + `@Getter` + `@Setter` | 프레임워크가 setter로 바인딩 |

```java
// ✅ 올바른 예 — 일반 Request/Response는 record
public record SignUpRequest(
        @Email String email,
        @NotBlank String password,
        @NotBlank String nickname
) {}

// ✅ 올바른 예 — 폼 바인딩이 필요한 DTO는 class
@Getter
@Setter
public class ClientCreateRequest {
    private String clientId;
    private String clientName;
}

// ❌ 잘못된 예
@Data                           // @Setter 포함 — record 대신 @Data를 쓰지 않는다
public class SignUpRequest { }
```
