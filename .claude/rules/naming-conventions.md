# 네이밍 규칙

이 파일은 클래스·파일 이름 작성 시 항상 따라야 할 규칙을 정의한다.

---

## 추상 클래스 — `Abstract` 접두사

추상 클래스는 항상 `Abstract`로 시작한다. `Base` 접두사는 사용하지 않는다.

```java
// ✅ 올바른 예
AbstractUserService
AbstractTokenProvider

// ❌ 잘못된 예
BaseUserService    // Base 접두사 금지
UserServiceBase    // 접두사가 아닌 접미사 위치
```

---

## 인터페이스 — 접두사 없음

인터페이스는 순수 역할명만 사용한다. `I` 접두사를 붙이지 않는다.

```java
// ✅ 올바른 예
UserService
ClientRepository
TokenProvider

// ❌ 잘못된 예
IUserService       // I 접두사 금지
UserServiceIF      // IF 접미사 금지
```

---

## Service 구현체 — 의미 있는 이름

Service 구현체는 구현 방식이나 특성을 이름에 담는다. 단순 `Impl` 접미사는 지양한다.

```java
// ✅ 올바른 예
SimpleAdminClientService   // 단순 위임 구현
CachedUserService          // 캐시 적용 구현
JwtTokenProvider           // JWT 방식 구현

// ❌ 잘못된 예
UserServiceImpl            // 의미 없는 Impl 접미사
AdminClientServiceImpl
```

---

## Repository 커스텀 구현체 — `{Interface}Impl`

Spring Data JPA의 커스텀 구현체는 `{Repository인터페이스명}Impl`로 지어야 Spring이 자동으로 연결한다. 이 경우에만 `Impl` 접미사를 허용한다.

```java
// ✅ Spring Data JPA 관례 — Impl 접미사 필수
ClientRepository            ← 인터페이스
ClientRepositoryImpl        ← Spring이 자동 연결하는 커스텀 구현체
```

---

## Security Handler — 접미사 규칙

Spring Security의 `AuthenticationSuccessHandler`, `AuthenticationFailureHandler` 등을 구현한 클래스는 **역할 + `Handler`** 접미사를 사용한다.

```java
// ✅ 올바른 예
JsonAuthenticationSuccessHandler   // JSON 응답 전용 성공 핸들러
JsonAuthenticationFailureHandler   // JSON 응답 전용 실패 핸들러
JsonLogoutSuccessHandler           // JSON 응답 전용 로그아웃 핸들러
ClientAwareLoginUrlAuthenticationEntryPoint  // 클라이언트별 로그인 URL 분기

// ❌ 잘못된 예
AuthSuccessHandlerImpl             // 의미 없는 Impl 접미사
LoginHandler                       // 역할 불분명 (성공? 실패?)
```
