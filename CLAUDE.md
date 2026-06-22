# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Test Commands

```bash
# 빌드
./gradlew build

# 테스트 전체 실행
./gradlew test

# 단일 테스트 클래스 실행
./gradlew test --tests "com.auth.user.application.UserServiceTest"

# 단일 테스트 메서드 실행
./gradlew test --tests "com.auth.user.application.UserServiceTest.findById_존재하는_사용자_조회시_UserResponse_반환"

# 빌드 없이 테스트만
./gradlew test -x build
```

## Architecture Overview

Spring Boot 4 / Java 21 기반의 **OAuth2 Authorization Server**다. 세 가지 역할을 하나의 애플리케이션에서 처리한다.

### 세 가지 보안 영역

`SecurityFilterChain`이 `@Order`로 우선순위가 결정된다.

| Order | 클래스 | 역할 | 경로 |
|-------|--------|------|------|
| 1 | `AuthorizationServerConfig` | OAuth2 인가 서버 엔드포인트 | `/oauth2/**`, `/.well-known/**` 등 |
| 2 | `ResourceServerConfig` | REST API (Stateless, JWT) | `/api/**` |
| 3 | `SecurityConfig` | 일반 사용자 로그인·소셜 로그인 | 나머지 |

### 데이터 저장소

- **PostgreSQL** — JPA Entity(User, Role, SocialAccount) + Flyway 마이그레이션, `JdbcRegisteredClientRepository`로 OAuth2 클라이언트 저장
- **Redis** — `spring-session-data-redis`로 OAuth2 인가 흐름 세션 관리
- 스키마는 `src/main/resources/db/migration/`에서 관리한다

### 토큰 구조

RSA 키페어(`RsaProperty`)로 JWT를 서명한다. `OAuth2TokenCustomizer`가 Access Token에 `roles`와 `user_id` 클레임을 추가한다. Resource Server는 `roles` 클레임을 권한으로 읽는다(`JwtGrantedAuthoritiesConverter`).

### 클라이언트 관리

`RegisteredClientRepository`(JDBC)가 Spring Authorization Server의 공식 저장소 역할을 하고, `ClientRepository`(커스텀 JDBC)는 목록 조회·삭제 등 부가 쿼리를 처리한다. 두 저장소가 같은 `oauth2_registered_client` 테이블을 바라본다.

### 소셜 로그인

`SocialOAuth2UserService`가 소셜 계정을 처리한다. 사용자가 처음 로그인하면 `SocialAccount`와 연결된 `User`를 자동 생성한다.

### 외부 설정값

| 키 | 바인딩 클래스 | 설명 |
|----|--------------|------|
| `auth.issuer-uri` | `AuthProperty` | Authorization Server issuer URI |
| `auth.allowed-origins` | `SecurityConfig` (`@Value`) | CORS 허용 origin (콤마 구분) |
| `auth.rsa.*` | `RsaProperty` | RSA 공개키·개인키 |

### 컨벤션 규칙 위치

코드 작성 규칙은 `.claude/rules/`에 있다. 새 코드 작성 전에 반드시 확인한다.

- `common-conventions.md` — Lombok, 유틸리티 클래스, 상수
- `directory-conventions.md` — 패키지 구조 (기능적 응집도 우선)
- `naming-conventions.md` — 클래스명 규칙 (인터페이스, 구현체, 추상 클래스)
- `exception-conventions.md` — ErrorCode 접두사, AuthException, 응답 형식
- `controller-conventions.md` — Controller 구조
- `logging-conventions.md` — 로그 태그 형식, 레벨 기준
- `test-conventions.md` — 테스트 어노테이션 선택, given/when/then 구조
