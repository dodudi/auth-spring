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

# Run the application
./gradlew bootRun --args='--spring.profiles.active=local'

# Run all tests
./gradlew test

# Run a single test class
./gradlew test --tests "com.auth.SomeTest"

# Run a single test method
./gradlew test --tests "com.auth.SomeTest.methodName"

# Clean build
./gradlew clean build
```

---

## Architecture Overview

**Spring Boot 4.0.5 / Java 21** OAuth2 Authorization Server. Root package: `com.auth`.

### Key technology choices

| Concern | Technology |
|---|---|
| Auth | Spring Security OAuth2 Authorization Server |
| Persistence | Spring Data JPA + Flyway migrations |
| DB (prod) | PostgreSQL |
| DB (dev/test) | H2 in-memory |
| Redis | Spring Data Redis (`StringRedisTemplate`) + Spring Session (`@EnableRedisHttpSession`) |
| Template | Thymeleaf (관리자 패널 전체 + OAuth2 에러 화면) |
| API docs | SpringDoc OpenAPI (`/swagger-ui.html`) |
| Metrics | Micrometer + Prometheus |
| Boilerplate | Lombok |

### Jackson 3.x (중요)

Spring Boot 4.x는 **Jackson 3.x**를 사용한다. import 경로가 Jackson 2.x와 다르다.

```java
// Jackson 3.x (이 프로젝트에서 사용)
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.JsonNode;

// Jackson 2.x (사용 금지 — Spring Boot 3.x 이하)
import com.fasterxml.jackson.databind.ObjectMapper;
```

`SessionConfig`의 `JsonMapper`, `JacksonModule`, `BasicPolymorphicTypeValidator` 등도 모두 `tools.jackson.*` 패키지를 사용한다.

### Library Versions

| Library | Version |
|---|---|
| Java | 21 (LTS, toolchain 설정) |
| Spring Boot | 4.0.5 |
| Spring Dependency Management | 1.1.7 |
| SpringDoc OpenAPI | 3.0.2 (명시적 버전, BOM 미포함) |
| Spring Security OAuth2 Authorization Server | Spring Boot BOM 관리 |
| Spring Data JPA / Redis / Flyway / H2 / PostgreSQL / Lombok | Spring Boot BOM 관리 |

> 버전 확인: `./gradlew dependencies`

---

## 설정 파일 구조 (Spring Profile)

| 파일 | 활성 프로파일 | 용도 |
|---|---|---|
| `application.yml` | 공통 (항상 로드) | issuer URI 기본값(localhost), JPA, Flyway, SpringDoc, Actuator |
| `application-local.yml` | `local` | 개발 환경 설정 (H2, 로컬 Redis, RSA 키, CORS 허용 origin) |
| `application-prod.yml` | `prod` | 배포 환경 설정 (PostgreSQL, 운영 Redis, 환경변수 주입) |

```bash
# 로컬 개발
./gradlew bootRun --args='--spring.profiles.active=local'

# 운영 배포
java -jar app.jar --spring.profiles.active=prod
```

> `application-local.yml`은 `.gitignore`에 추가해 민감한 로컬 설정이 커밋되지 않도록 한다.

### application-local.yml 필수 프로퍼티

| 프로퍼티 | 설명 |
|---|---|
| `auth.rsa.private-key` | Base64 인코딩된 RSA 개인키 (PKCS8) |
| `auth.rsa.public-key` | Base64 인코딩된 RSA 공개키 (X509) |
| `auth.allowed-origins` | CORS 허용 origin (쉼표 구분, 예: `http://localhost:3000`) |

### application-prod.yml 환경변수 목록

모든 민감 값은 환경변수로 주입한다.

| 환경변수 | 설명 |
|---|---|
| `AUTH_ISSUER_URI` | Authorization Server issuer URI |
| `RSA_PRIVATE_KEY` | Base64 인코딩된 RSA 개인키 (PKCS8) |
| `RSA_PUBLIC_KEY` | Base64 인코딩된 RSA 공개키 (X509) |
| `ALLOWED_ORIGINS` | CORS 허용 origin (쉼표 구분) |
| `OAUTH2_CLIENT_ID` | Google OAuth2 클라이언트 ID |
| `OAUTH2_CLIENT_SECRET` | Google OAuth2 클라이언트 시크릿 |
| `OAUTH2_REDIRECT_URI` | 인가 코드 수신 Redirect URI |
| `OAUTH2_POST_LOGOUT_REDIRECT_URI` | 로그아웃 후 Redirect URI |
| `DB_URL` | PostgreSQL JDBC URL |
| `DB_USERNAME` | DB 사용자명 |
| `DB_PASSWORD` | DB 비밀번호 |
| `REDIS_HOST` | Redis 호스트 |
| `REDIS_PORT` | Redis 포트 (기본값: `6379`) |
| `REDIS_PASSWORD` | Redis 비밀번호 (없으면 빈 값) |

HikariCP: `maximum-pool-size=10`, `minimum-idle=5`.
H2 콘솔: prod에서 `enabled: false`.
로그 레벨: `com.auth=INFO`, `org.springframework.security=WARN`.

---

## Security Filter Chain

4개의 `SecurityFilterChain`이 `@Order`로 우선순위가 결정된다.

| Order | Config 클래스 | 대상 요청 | 역할 |
|---|---|---|---|
| 1 | `AuthorizationServerConfig` | OAuth2 엔드포인트 | Authorization Server (토큰 발급, OIDC 등) |
| 2 | `AdminSecurityConfig` | `/admin/**` | 관리자 패널 (세션 기반, CSRF 활성화) |
| 3 | `ResourceServerConfig` | `/api/**` | Resource Server (JWT 검증, Stateless) |
| 4 | `SecurityConfig` | 나머지 전체 | formLogin + oauth2Login (사용자 인증 UI) |

### Authorization Server Chain (AuthorizationServerConfig)

- **Grant Type**: Authorization Code, Refresh Token
- **Scope**: `openid`, `profile`
- **PKCE**: `requireProofKey(false)` — 현재 비활성화 상태
- **Consent**: `requireAuthorizationConsent(true)` — 동의 화면 활성화
- **JWT Access Token**: `roles`·`user_id` 클레임 추가 (`OAuth2TokenCustomizer`)
- **RSA 키**: `auth.rsa.private-key`/`auth.rsa.public-key` 프로퍼티로 주입 (`RsaProperty`), key ID = `"auth-server-key"`
- **RegisteredClientRepository**: `JdbcRegisteredClientRepository` (DB 공유, Scale Out 안전)
- **OAuth2AuthorizationService**: Bean 미등록 → **`InMemoryOAuth2AuthorizationService` 기본값** (Scale Out 위험)
- **OAuth2AuthorizationConsentService**: Bean 미등록 → **`InMemoryOAuth2AuthorizationConsentService` 기본값** (Scale Out 위험)
- **에러 핸들링**: `CustomAuthorizationServerFailureHandler` — `/oauth2/authorize` 실패 시 `/oauth/error?error=...`로 리다이렉트
- **미인증 진입점**: `ClientAwareLoginUrlAuthenticationEntryPoint` — `client_id`로 `RegisteredClient`를 조회해 `ClientSettings`의 `loginPageUri` 값으로 리다이렉트. `loginPageUri` 미설정 시 `/oauth/error`로 리다이렉트

### Admin Chain (AdminSecurityConfig)

- `/admin/login` — 별도 로그인 페이지, `permitAll()`
- 나머지 `/admin/**` — `ROLE_ADMIN` 필요
- 로그인 성공 후 `/admin/clients`로 이동
- **CSRF 활성화** (다른 체인과 달리)
- 세션 기반 인증 (Spring Session + Redis로 공유됨)

### Resource Server Chain (ResourceServerConfig)

- JWT의 `roles` 클레임을 `GrantedAuthority`로 변환 (`JwtGrantedAuthoritiesConverter`)
- Authority prefix 없음 (`ROLE_USER` 그대로 사용)
- 메서드 보안: `@EnableMethodSecurity` → `@PreAuthorize` 사용 가능
- `/api/v1/users/signup` — 인증 없이 접근 허용 (나머지 `/api/**`는 JWT 필수)
- `SessionCreationPolicy.STATELESS` — 세션 미사용

### Default Chain (SecurityConfig)

- 로그인 처리: `POST /login` (Form), `GET /oauth2/authorization/google` (소셜)
- **성공 핸들러**: `JsonAuthenticationSuccessHandler` — SavedRequest가 있으면 리다이렉트(OAuth2 흐름 복귀), 없으면 JSON 반환
- **실패 핸들러**: `JsonAuthenticationFailureHandler` — 401 + `ErrorCode.INVALID_CREDENTIALS` JSON 반환
- **소셜 로그인**: `SocialOAuth2UserService` — Google 사용자 조회/생성/연결 처리
- `/oauth/error` — 명시적 `permitAll()`
- CORS 허용 origin: `${auth.allowed-origins}` 프로퍼티 (쉼표 구분 다중 origin 지원)
- CSRF: 비활성화

---

## OAuth2 에러 처리 흐름

`/oauth2/authorize` 요청 중 에러 발생 시:

```
CustomAuthorizationServerFailureHandler
  └── sendRedirect("/oauth/error?error=invalid_request&error_description=...")
        └── OAuthErrorController (@Controller, security/api/)
              └── model에 error, errorDescription 추가
                    └── templates/oauth-error.html (Thymeleaf 렌더링)
```

---

## Scale Out 현황

| 항목 | 상태 | 비고 |
|---|---|---|
| `RegisteredClient` | ✅ 안전 | `JdbcRegisteredClientRepository` — DB 공유 |
| RSA 키 | ✅ 안전 | 프로퍼티 주입 — 모든 인스턴스 동일 키 |
| formLogin 세션 | ✅ 안전 | `SessionConfig` — `@EnableRedisHttpSession`, namespace `spring:session:auth`, TTL 1시간 |
| Authorization Code / Refresh Token | ⚠️ 위험 | `InMemoryOAuth2AuthorizationService` 기본값 → `JdbcOAuth2AuthorizationService` 필요 |
| Consent 기록 | ⚠️ 위험 | `InMemoryOAuth2AuthorizationConsentService` 기본값 → `JdbcOAuth2AuthorizationConsentService` 필요 |

---

## API Endpoints

### User (`/api/v1/users`)

| Method | Path | 인증 | 설명 |
|---|---|---|---|
| `POST` | `/api/v1/users/signup` | 불필요 | 회원가입 |
| `POST` | `/api/v1/users/verify-email` | JWT 필요 | 이메일 인증 토큰 확인 |
| `GET` | `/api/v1/users/me` | `ROLE_USER` | 내 정보 조회 |
| `PATCH` | `/api/v1/users/me` | `ROLE_USER` | 닉네임 수정 |
| `DELETE` | `/api/v1/users/me` | `ROLE_USER` | 회원 탈퇴 (status → `WITHDRAWN`) |

### Admin (`/admin`) — `ROLE_ADMIN` 전용

| Method | Path | 설명 |
|---|---|---|
| `GET` | `/admin/clients` | 클라이언트 목록 |
| `GET` | `/admin/clients/new` | 클라이언트 생성 폼 |
| `POST` | `/admin/clients/new` | 클라이언트 생성 |
| `GET` | `/admin/clients/{id}/edit` | 클라이언트 수정 폼 |
| `POST` | `/admin/clients/{id}/edit` | 클라이언트 수정 |
| `POST` | `/admin/clients/{id}/delete` | 클라이언트 삭제 |
| `POST` | `/admin/clients/{id}/regenerate-secret` | 시크릿 재발급 (단 한 번만 평문 노출) |

### OAuth2 / 기타

| Method | Path | 설명 |
|---|---|---|
| `GET` | `/oauth/error` | OAuth2 인가 오류 페이지 (Thymeleaf, `error` + `error_description` 파라미터) |
| `GET` | `/swagger-ui.html` | API 문서 |
| `GET` | `/actuator/health`, `/actuator/info`, `/actuator/prometheus` | Actuator |

---

## Database Schema

Flyway 마이그레이션 파일: `src/main/resources/db/migration/`

| 파일 | 내용 |
|---|---|
| `V1__init_domain_tables.sql` | `users`, `social_accounts`, `roles`, `user_roles` |
| `V2__init_oauth2_tables.sql` | `oauth2_registered_client`, `oauth2_authorization_consent`, `oauth2_authorization` |
| `V3__insert_default_roles.sql` | `ROLE_USER`, `ROLE_ADMIN` 기본 역할 삽입 |

### 주요 테이블

- `users`: PK = `UUID`, `email` unique, `status` (`ACTIVE` / `SUSPENDED` / `WITHDRAWN`), `email_verified`
- `roles`: PK = `BIGSERIAL`, `name` unique
- `user_roles`: `user_id` + `role_id` 복합 PK (다대다 조인 테이블)
- `oauth2_authorization`: Spring Authorization Server 표준 스키마, Authorization Code / Access Token / Refresh Token 저장

---

## Redis 사용

| 용도 | 클래스 | 키 패턴 | TTL |
|---|---|---|---|
| 이메일 인증 토큰 | `UserService` (`StringRedisTemplate`) | `email:verify:{token}` | 24시간 |
| 로그인 세션 | `SessionConfig` (`@EnableRedisHttpSession`) | `spring:session:auth:*` | 1시간 |

> 현재 `signUp()` 내 Redis 토큰 저장 및 이메일 발송 코드가 주석 처리되어 있어, `verifyEmail()` 엔드포인트가 실질적으로 동작하지 않는다.

---

## 알려진 버그 / TODO

- **이메일 인증 미완성**: `UserService.signUp()`에서 Redis 토큰 저장과 메일 발송 로직이 주석 처리됨. 연동 전까지 `POST /api/v1/users/verify-email`은 항상 `T001 INVALID_TOKEN` 에러를 반환한다.
- **`CustomUserDetailsService` 다중 역할 버그**: `roles` 매핑 시 `Stream.reduce`로 역할명을 콤마로 이어붙인 뒤 단일 `SimpleGrantedAuthority`로 감싼다. `ROLE_USER`, `ROLE_ADMIN` 두 역할을 가지면 `"ROLE_USER,ROLE_ADMIN"` 하나의 authority가 생성되어 권한 체크가 모두 실패한다. 현재 `signUp()`에서 `ROLE_USER` 하나만 부여하므로 당장 문제는 없지만, 다중 역할 도입 전에 반드시 수정해야 한다.
- **Scale Out 대응 미완성**: 위 "Scale Out 현황" 섹션의 ⚠️ 항목 참고.

---

## 패키지 구조 (도메인 기반)

기술 계층이 아닌 비즈니스 도메인을 기준으로 패키지를 구성한다.

```
com.auth
├── common/
│   ├── exception/     # ErrorCode (enum), AuthException, GlobalExceptionHandler
│   └── response/      # ApiResponse<T> record
├── user/
│   ├── api/           # UserController
│   ├── application/   # UserService
│   ├── domain/        # User, Role, SocialAccount, *Repository, UserStatus, SocialProvider
│   └── dto/           # SignUpRequest, UpdateNicknameRequest, VerifyEmailRequest, UserResponse
├── admin/
│   ├── api/           # AdminClientController, AdminLoginController
│   ├── application/   # AdminClientManagement (interface), SimpleAdminClientService
│   ├── domain/        # ClientRepository (interface), ClientRepositoryImpl (raw JDBC)
│   └── dto/           # ClientSummary, ClientDetail, ClientCreateRequest, ClientUpdateRequest, SecretRevealResponse
├── security/
│   ├── api/           # OAuthErrorController
│   ├── application/   # CustomUserDetailsService, SocialOAuth2UserService
│   ├── handler/       # JsonAuthenticationSuccessHandler, JsonAuthenticationFailureHandler,
│   │                  # CustomAuthorizationServerFailureHandler, ClientAwareLoginUrlAuthenticationEntryPoint
│   └── property/      # RsaProperty
└── config/            # 보안·인프라 설정 Bean 정의
    # AuthorizationServerConfig — OAuth2/OIDC, JWT, JWKSource
    # AdminSecurityConfig      — /admin/** 체인 (@Order 2)
    # ResourceServerConfig     — /api/** 체인, @EnableMethodSecurity
    # SecurityConfig           — Default 체인, CORS, PasswordEncoder
    # SessionConfig            — @EnableRedisHttpSession, Jackson 직렬화 설정
    # JpaConfig                — @EnableJpaAuditing
```

### admin/domain 주의사항

`ClientRepository`와 `ClientRepositoryImpl`은 JPA를 사용하지 않는다. Spring Authorization Server가 관리하는 `oauth2_registered_client` 테이블을 직접 raw JDBC(`JdbcTemplate`)로 조회한다. 클라이언트 생성·수정은 `JdbcRegisteredClientRepository`를 통해 처리한다.

### ClientSettings 커스텀 키

`RegisteredClient.ClientSettings`에 비표준 키 `loginPageUri`를 저장해 서비스별 로그인 페이지를 관리한다. `ClientAwareLoginUrlAuthenticationEntryPoint`가 이 값을 읽어 미인증 요청을 해당 서비스 로그인 페이지로 리다이렉트한다.

---

## 코딩 컨벤션

- **DI**: `@RequiredArgsConstructor` + `final` 필드. `@Data` 사용 금지 (엔티티에 특히).
- **엔티티**: `domain/` 서브패키지, ID 타입 `Long` 또는 `UUID`. `@NoArgsConstructor(access = AccessLevel.PROTECTED)`, `@Builder`는 `private` 생성자에.
- **DTO**: `record` 타입 우선. Bean Validation 애노테이션은 DTO에만 적용.
- **API 응답**: `ResponseEntity<ApiResponse<T>>`. HTTP 상태는 `ResponseEntity`, body 형식은 `ApiResponse<T>`.
- **예외**: `RuntimeException` 상속, `ErrorCode` enum으로 관리. `GlobalExceptionHandler`(`@RestControllerAdvice`)에서 일괄 처리.

```java
// ErrorCode 추가 예시 — httpStatus 반드시 포함
NEW_ERROR(HttpStatus.BAD_REQUEST, "X001", "오류 메시지");

// 응답 예시
return ResponseEntity.ok(ApiResponse.ok(data));
return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ApiResponse.fail(ErrorCode.USER_NOT_FOUND));
```

---

## Project Rules

### 응답 언어

Claude는 이 프로젝트에서 항상 **한국어**로 응답한다. 코드와 주석은 영어로 작성한다.

### Database migrations

마이그레이션 파일: `src/main/resources/db/migration/V{version}__{description}.sql`.
스크립트는 PostgreSQL 호환으로 작성한다. 테스트 환경(H2)에서는 H2 호환 모드 설정이 필요할 수 있다.

### Testing

`@SpringBootTest`로 전체 컨텍스트를 로드하는 통합 테스트를 기본으로 사용한다.
H2가 테스트 JPA 런타임이며, Redis 테스트는 embedded Redis 지원을 사용한다.

### Dockerfile

- **멀티 스테이지 빌드** 필수: `builder`(JDK) → 실행(JRE) 2단계로 이미지 크기를 최소화한다.
- **베이스 이미지**: `eclipse-temurin:21-jdk-jammy`(빌드) / `eclipse-temurin:21-jre-jammy`(실행). Java 버전이 변경되면 두 이미지 모두 함께 변경한다.
- **레이어 캐시 최적화**: `gradlew` + `gradle/` + `build.gradle` + `settings.gradle` 복사 → `dependencies` 실행 → `src/` 복사 순서를 유지한다. 소스 변경 시 의존성 레이어가 재빌드되지 않는다.
- **테스트 제외**: `bootJar` 시 `-x test`를 붙인다. 테스트는 CI 파이프라인에서 별도로 실행한다.
- **비루트 실행**: `addgroup` / `adduser`로 전용 시스템 계정을 생성하고 `USER`로 전환한 뒤 애플리케이션을 실행한다.
- **프로파일 주입 금지**: `SPRING_PROFILES_ACTIVE` 등 환경 설정은 이미지에 굽지 않고 컨테이너 실행 시 `-e`로 주입한다.

```bash
# 빌드
docker build -t auth-spring .

# 실행
docker run -p 8080:8080 \
  -e SPRING_PROFILES_ACTIVE=prod \
  -e DB_URL=jdbc:postgresql://host:5432/db \
  -e DB_USERNAME=user \
  -e DB_PASSWORD=secret \
  -e REDIS_HOST=host \
  -e RSA_PRIVATE_KEY=... \
  -e RSA_PUBLIC_KEY=... \
  auth-spring
```
