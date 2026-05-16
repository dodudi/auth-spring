# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 참고 자료

Spring Authorization Server 관련 클래스·패키지를 조회할 때는 아래 공식 API 문서를 참고한다.

- **Spring Authorization Server API Javadoc**: https://docs.spring.io/spring-authorization-server/docs/current/api/org/springframework

> 패키지 경로나 클래스 시그니처가 불확실할 때 반드시 위 문서를 먼저 확인한다.
> 특히 Spring Boot 4.x / Spring Security 7.x 환경에서는 패키지 위치가 이전 버전과 다를 수 있다.

---

## Commands

```bash
# Build
./gradlew build

# Run (로컬 개발)
./gradlew bootRun --args='--spring.profiles.active=local'

# Test 전체
./gradlew test

# 단일 테스트 클래스
./gradlew test --tests "com.auth.SomeTest"

# 단일 테스트 메서드
./gradlew test --tests "com.auth.SomeTest.methodName"

# Clean build
./gradlew clean build
```

---

## 기술 스택

| 관심사 | 기술 |
|---|---|
| Runtime | Spring Boot 4.0.5 / Java 21 |
| Auth | Spring Security OAuth2 Authorization Server |
| Persistence | Spring Data JPA + Flyway |
| DB (prod) | PostgreSQL 17 |
| DB (test) | H2 (PostgreSQL 호환 모드) |
| Redis | Spring Session (`@EnableRedisHttpSession`) + `StringRedisTemplate` |
| Template | Thymeleaf (관리자 패널, OAuth2 에러 화면) |
| API docs | SpringDoc OpenAPI 3.0.2 (`/swagger-ui.html`) |
| Metrics | Micrometer + Prometheus (`/actuator/prometheus`) |

### Jackson 3.x (중요)

Spring Boot 4.x는 **Jackson 3.x**를 사용한다. import 경로가 2.x와 다르다.

```java
// Jackson 3.x — 이 프로젝트에서 사용
import tools.jackson.databind.ObjectMapper;

// Jackson 2.x — 사용 금지
import com.fasterxml.jackson.databind.ObjectMapper;
```

---

## Spring Profile 구성

| 파일 | 프로파일 | 용도 |
|---|---|---|
| `application.yml` | 공통 | issuer URI, JPA, Flyway, SpringDoc, Actuator |
| `application-local.yml` | `local` | H2, 로컬 Redis, RSA 키, CORS (.gitignore) |
| `application-prod.yml` | `prod` | PostgreSQL, 운영 Redis, 환경변수 주입 |
| `src/test/resources/application.yml` | test 기본 | H2, Redis localhost:6379 |
| `src/test/resources/application-test.yml` | `test` | H2 + Flyway 활성화, RSA placeholder |

`application-local.yml`은 `.gitignore`에 포함 — 직접 생성해야 한다.  
필수 프로퍼티: `auth.rsa.private-key`, `auth.rsa.public-key`, `auth.allowed-origins`

---

## Security Filter Chain (4개, @Order 우선순위)

| Order | 클래스 | 대상 | 역할 |
|---|---|---|---|
| 1 | `AuthorizationServerConfig` | OAuth2 엔드포인트 | 토큰 발급, OIDC |
| 2 | `AdminSecurityConfig` | `/admin/**` | 세션 기반, CSRF 활성화 |
| 3 | `ResourceServerConfig` | `/api/**` | JWT 검증, Stateless |
| 4 | `SecurityConfig` | 나머지 전체 | formLogin + oauth2Login |

**AuthorizationServerConfig 핵심 동작:**
- `JdbcRegisteredClientRepository` — DB 공유, Scale Out 안전
- `InMemoryOAuth2AuthorizationService` 기본값 — Scale Out 위험
- `OAuth2TokenCustomizer`: Access Token에 `roles`, `user_id` 클레임 추가
- `ClientAwareLoginUrlAuthenticationEntryPoint`: `RegisteredClient.ClientSettings`의 커스텀 키 `loginPageUri`를 읽어 서비스별 로그인 페이지로 리다이렉트

**SocialOAuth2UserService 처리 흐름:**
1. `[SOCIAL_LOGIN]` — 기존 소셜 계정 재로그인
2. `[SOCIAL_LOGIN_LINK]` — 동일 이메일에 소셜 계정 연동
3. `[SOCIAL_LOGIN_NEW]` — 신규 유저 생성

소셜 로그인 후 principal name은 이메일을 `"identifier"` 키에 통일해 사용한다(`authentication.getName()` = 이메일).

---

## 패키지 구조

```
com.auth
├── common/
│   ├── exception/     # ErrorCode (enum), AuthException, GlobalExceptionHandler
│   ├── filter/        # RequestLoggingFilter
│   ├── response/      # ApiResponse<T> record
│   └── util/          # HttpUtils
├── user/
│   ├── api/           # UserController
│   ├── application/   # UserService
│   ├── domain/        # User, Role, SocialAccount, *Repository, UserStatus, SocialProvider
│   └── dto/           # SignUpRequest, UpdateNicknameRequest, UserResponse
├── admin/
│   ├── api/           # AdminClientController, AdminLoginController
│   ├── application/   # AdminClientManagement (interface), SimpleAdminClientService
│   ├── domain/        # ClientRepository (JdbcTemplate 직접 사용, JPA 아님)
│   └── dto/           # ClientSummary, ClientDetail, ClientCreateRequest, ClientUpdateRequest, SecretRevealResponse
├── security/
│   ├── api/           # OAuthErrorController
│   ├── application/   # CustomUserDetailsService, SocialOAuth2UserService
│   ├── handler/       # JsonAuthenticationSuccessHandler, JsonAuthenticationFailureHandler,
│   │                  # CustomAuthorizationServerFailureHandler, ClientAwareLoginUrlAuthenticationEntryPoint
│   └── property/      # RsaProperty
└── config/            # AuthorizationServerConfig, AdminSecurityConfig, ResourceServerConfig,
                       # SecurityConfig, SessionConfig, JpaConfig
```

`admin/domain`은 JPA를 사용하지 않는다. `oauth2_registered_client` 테이블을 raw `JdbcTemplate`으로 조회하고, 생성·수정은 `JdbcRegisteredClientRepository`를 통한다.

---

## 코딩 컨벤션

- **DI**: `@RequiredArgsConstructor` + `final` 필드. `@Data` 사용 금지.
- **엔티티**: `@NoArgsConstructor(access = AccessLevel.PROTECTED)`, `@Builder`는 `private` 생성자에.
- **DTO**: `record` 타입 우선. Bean Validation은 DTO에만.
- **API 응답**: `ResponseEntity<ApiResponse<T>>`.
- **예외**: `AuthException(ErrorCode)` + `GlobalExceptionHandler`에서 일괄 처리.

```java
// ErrorCode 추가 예시 — prefix: C(Common) U(User) CL(Client) T(Token)
NEW_ERROR(HttpStatus.BAD_REQUEST, "X001", "오류 메시지");

// 응답 예시
return ResponseEntity.ok(ApiResponse.ok(data));
return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ApiResponse.fail(ErrorCode.USER_NOT_FOUND));
```

---

## 로그 태그 (Grafana 연동)

코드 내 구조화 로그 태그 — Loki 쿼리 및 Grafana 대시보드가 이 태그를 기반으로 집계한다.

| 태그 | 위치 | 의미 |
|---|---|---|
| `[USER_SIGNUP]` | `UserService.signUp` | 폼 회원가입 |
| `[USER_WITHDRAW]` | `UserService.withdraw` | 회원 탈퇴 |
| `[SOCIAL_LOGIN]` | `SocialOAuth2UserService` | 소셜 재로그인 |
| `[SOCIAL_LOGIN_LINK]` | `SocialOAuth2UserService` | 이메일 일치 계정 연동 |
| `[SOCIAL_LOGIN_NEW]` | `SocialOAuth2UserService` | 소셜 신규 가입 |
| `[LOGIN_SUCCESS]` | `JsonAuthenticationSuccessHandler` | 폼 로그인 성공 |
| `[LOGIN_FAILURE]` | `JsonAuthenticationFailureHandler` | 폼 로그인 실패 |

---

## 테스트

- `BaseIntegrationTest` 상속: `@SpringBootTest + @AutoConfigureMockMvc + @ActiveProfiles("test") + @Transactional`
- Redis는 Testcontainers (`GenericContainer<>("redis:7")`), RSA 키는 동적 생성 — `@DynamicPropertySource`로 주입
- `AuthSpringApplicationTests`는 `@ActiveProfiles` 없음 — CI에서 Redis service container 필요

```bash
# 테스트 리포트
build/reports/tests/test/index.html
```

---

## 데이터베이스

Flyway 마이그레이션: `src/main/resources/db/migration/`

| 파일 | 내용 |
|---|---|
| `V1__init_domain_tables.sql` | `users`, `social_accounts`, `roles`, `user_roles` |
| `V2__init_oauth2_tables.sql` | `oauth2_registered_client`, `oauth2_authorization_consent`, `oauth2_authorization` |
| `V3__insert_default_roles.sql` | `ROLE_USER`, `ROLE_ADMIN` 기본 역할 삽입 |

마이그레이션은 PostgreSQL 호환으로 작성. 새 파일: `V{n}__{description}.sql`

---

## CI/CD

상세 설계: `CICD.md` 참고

| 워크플로 | 트리거 | 내용 |
|---|---|---|
| `ci.yml` | PR to main, 기능 브랜치 push | 테스트 실행 (Redis service container 포함) |
| `docker-publish.yml` | main push, `v*.*.*` 태그 | test → build(amd64+arm64) → merge → deploy(SSH, main만) |

배포 대상: 라즈베리 파이, `appleboy/ssh-action`으로 SSH 접속 후 `docker compose up`.  
필요 Secrets: `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`, `DEPLOY_HOST`, `DEPLOY_USER`, `DEPLOY_SSH_KEY`

---

## 알려진 버그 / Scale Out 위험

| 항목 | 상태 | 비고 |
|---|---|---|
| 이메일 인증 | 미완성 | `UserService.signUp()`의 Redis 토큰 저장·메일 발송 로직 주석 처리됨 |
| 다중 역할 권한 버그 | 잠재적 | `CustomUserDetailsService`가 역할을 콤마로 이어붙여 단일 authority 생성 — 현재는 단일 역할만 부여되어 미발현 |
| Authorization Code / Refresh Token | ⚠️ Scale Out 위험 | `InMemoryOAuth2AuthorizationService` → `JdbcOAuth2AuthorizationService` 필요 |
| Consent 기록 | ⚠️ Scale Out 위험 | `InMemoryOAuth2AuthorizationConsentService` → `JdbcOAuth2AuthorizationConsentService` 필요 |

---

## 응답 언어

이 프로젝트에서 항상 **한국어**로 응답한다. 코드와 주석은 영어로 작성한다.
