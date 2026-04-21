# auth-spring

Spring Boot 기반 OAuth2 인증 서버. Google 소셜 로그인을 지원하며, Authorization Code 흐름을 제공합니다.

---

## 목차

1. [시스템 아키텍처](#시스템-아키텍처)
2. [SecurityFilter Chain](#securityfilter-chain)
3. [기술 스택](#기술-스택)
4. [데이터베이스 구조](#데이터베이스-구조)
5. [인증 흐름](#인증-흐름)
6. [API 명세](#api-명세)
7. [로컬 실행 방법](#로컬-실행-방법)

---

## 시스템 아키텍처

```mermaid
graph TB
    subgraph Clients["클라이언트"]
        SPA["SPA / 모바일 앱<br/>(Authorization Code)"]
    end

    subgraph AuthServer["auth-spring (이 서버)"]
        direction TB
        AS["Spring Authorization Server<br/>/oauth2/authorize<br/>/oauth2/token"]
        SEC["Spring Security<br/>Form Login / OAuth2 Login"]
        API["REST API<br/>/api/v1/users"]
    end

    subgraph Social["소셜 제공자"]
        GOOGLE["Google<br/>(OIDC)"]
    end

    subgraph Storage["저장소"]
        PG[("PostgreSQL<br/>사용자·토큰·클라이언트")]
        REDIS[("Redis<br/>이메일 인증 토큰<br/>세션")]
    end

    SPA -->|"① GET /oauth2/authorize"| AS
    AS -->|"② /login 리다이렉트"| SEC
    SEC -->|"③ 소셜 로그인 요청"| GOOGLE
    GOOGLE -->|"④ 콜백"| SEC
    SEC -->|"⑤ 인가코드 발급"| AS
    AS -->|"⑥ code"| SPA
    SPA -->|"⑦ POST /oauth2/token"| AS
    AS -->|"⑧ JWT"| SPA

    SPA -->|"Bearer JWT"| API
    API --- PG
    API --- REDIS
    AS --- PG
    AS --- REDIS
```

---

## SecurityFilter Chain

Spring Security는 요청이 들어오면 **Order 순서대로** 각 FilterChain의 `securityMatcher`를 확인하여, 처음으로 매칭되는 체인 하나만 적용합니다.

```mermaid
flowchart TD
    REQ([HTTP 요청])

    subgraph C1["Order 1 — AuthorizationServerConfig"]
        CHECK1{"AS 엔드포인트?\n/oauth2/**\n/connect/**\n/.well-known/**"}
        AS_AUTH{"세션 인증됨?"}
        AS_REDIRECT["302 → localhost:3000/login"]
        AS_HANDLE["토큰 발급 / 인가코드 처리\njwtTokenCustomizer → roles 클레임 추가"]
    end

    subgraph C2["Order 2 — ResourceServerConfig  ·  @EnableMethodSecurity"]
        CHECK2{"'/api/**' 에 해당?"}
        RS_PERMIT["permitAll ✅\nPOST /api/v1/users/signup"]
        RS_JWT["Bearer JWT 검증\nJwtAuthenticationConverter\n→ roles 클레임 → GrantedAuthority"]
        RS_METHOD["@PreAuthorize 평가\n→ Controller 처리"]
        RS_FAIL["401 Unauthorized"]
    end

    subgraph C3["Order 3 — SecurityConfig (Default)"]
        FL["Form Login / OAuth2 Login\nPOST /login → CustomUserDetailsService\nGET /oauth2/authorization/google → SocialOAuth2UserService"]
        FL_OK["세션 발급 후 OAuth2 흐름 복귀\n(JsonAuthenticationSuccessHandler)"]
        FL_FAIL["401 Unauthorized\n(JsonAuthenticationFailureHandler)"]
    end

    REQ --> CHECK1

    CHECK1 -->|"매칭"| AS_AUTH
    CHECK1 -->|"매칭 안 됨"| CHECK2

    AS_AUTH -->|"No"| AS_REDIRECT
    AS_AUTH -->|"Yes"| AS_HANDLE

    CHECK2 -->|"POST /signup"| RS_PERMIT
    CHECK2 -->|"그 외 /api/**"| RS_JWT
    CHECK2 -->|"매칭 안 됨"| FL

    RS_JWT -->|"유효"| RS_METHOD
    RS_JWT -->|"무효 / 없음"| RS_FAIL

    FL -->|"인증 성공"| FL_OK
    FL -->|"인증 실패"| FL_FAIL
```

### 요청별 담당 체인 요약

| 요청 | 체인 | 인증 방식 |
|---|---|---|
| `GET /oauth2/authorize` | Order 1 (AS) | 세션 — 미인증 시 `/login` 리다이렉트 |
| `POST /oauth2/token` | Order 1 (AS) | Client Basic Auth |
| `GET /oauth2/jwks` | Order 1 (AS) | 공개 엔드포인트 |
| `POST /api/v1/users/signup` | Order 2 (RS) | permitAll |
| `GET /api/v1/users/me` | Order 2 (RS) | Bearer JWT + `ROLE_USER` |
| `POST /login` | Order 3 (Default) | Form Login (ID/PW) |
| `GET /oauth2/authorization/google` | Order 3 (Default) | OAuth2 소셜 로그인 (Google) |
| `GET /login/oauth2/code/google` | Order 3 (Default) | Google 콜백 처리 |

---

## 기술 스택

| 분류 | 기술 | 버전 |
|---|---|---|
| 언어 | Java | 21 |
| 프레임워크 | Spring Boot | 4.0.5 |
| 인증 | Spring Authorization Server | (Boot BOM) |
| 소셜 로그인 | Spring OAuth2 Client | (Boot BOM) |
| ORM | Spring Data JPA + Hibernate | (Boot BOM) |
| DB 마이그레이션 | Flyway | (Boot BOM) |
| 캐시 / 세션 | Spring Data Redis, Spring Session | (Boot BOM) |
| DB (운영) | PostgreSQL | (Boot BOM) |
| DB (개발/테스트) | H2 (in-memory) | (Boot BOM) |
| API 문서 | SpringDoc OpenAPI | 3.0.2 |
| 모니터링 | Micrometer + Prometheus | (Boot BOM) |
| 빌드 | Gradle | - |

---

## 데이터베이스 구조

### 도메인 테이블 (V1 마이그레이션)

```mermaid
erDiagram
    users {
        UUID id PK
        VARCHAR email UK
        VARCHAR password "nullable (소셜 전용 계정)"
        VARCHAR nickname
        BOOLEAN email_verified
        VARCHAR status "ACTIVE / SUSPENDED / WITHDRAWN"
        TIMESTAMP created_at
        TIMESTAMP updated_at
    }

    roles {
        BIGINT id PK
        VARCHAR name UK "ROLE_USER / ROLE_ADMIN"
        VARCHAR description
    }

    user_roles {
        UUID user_id PK,FK
        BIGINT role_id PK,FK
        TIMESTAMP granted_at
    }

    social_accounts {
        UUID id PK
        UUID user_id FK
        VARCHAR provider "GOOGLE"
        VARCHAR provider_id
        TIMESTAMP created_at
    }

    users ||--o{ user_roles : "보유"
    roles ||--o{ user_roles : "부여됨"
    users ||--o{ social_accounts : "연동"
```

### OAuth2 서버 테이블 (V2 마이그레이션 — Spring Authorization Server 표준)

| 테이블 | 용도 |
|---|---|
| `oauth2_registered_client` | 등록된 OAuth2 클라이언트 |
| `oauth2_authorization` | 인가 상태 (code, access/refresh token) |
| `oauth2_authorization_consent` | 사용자 동의 내역 |

### 기본 데이터 (V3 마이그레이션)

| 역할 | 설명 |
|---|---|
| `ROLE_USER` | 일반 사용자 |
| `ROLE_ADMIN` | 관리자 |

---

## 인증 흐름

### 1. 이메일/비밀번호 로그인 → Authorization Code (SPA 대상)

```mermaid
sequenceDiagram
    actor User as 사용자
    participant SPA as SPA (localhost:3000)
    participant AS as auth-spring
    participant DB as PostgreSQL
    participant Redis as Redis

    User->>SPA: 로그인 버튼 클릭
    SPA->>AS: GET /oauth2/authorize<br/>?client_id=...&scope=openid profile
    AS->>SPA: 302 → /login (SavedRequest 저장)
    SPA->>AS: GET /login
    AS->>SPA: 로그인 페이지 (Form + Google 버튼)
    User->>AS: POST /login<br/>{email, password}
    AS->>DB: CustomUserDetailsService<br/>email로 사용자 조회
    DB->>AS: User + roles 반환
    AS->>AS: bcrypt.compare(password, hash) 검증
    AS->>Redis: 세션 저장 (Spring Session, 1시간)
    AS->>AS: JsonAuthenticationSuccessHandler<br/>SavedRequest 복원 → /oauth2/authorize 재처리
    AS->>SPA: 302 → /callback?code=<인가코드>
    SPA->>AS: POST /oauth2/token<br/>grant_type=authorization_code&code=...
    Note over AS: oauth2_authorization InMemory 저장
    AS->>SPA: access_token + refresh_token
```

### 2. 소셜 로그인 → Authorization Code (SPA 대상)

```mermaid
sequenceDiagram
    actor User as 사용자
    participant SPA as SPA (localhost:3000)
    participant AS as auth-spring
    participant Google as Google
    participant DB as PostgreSQL
    participant Redis as Redis

    User->>SPA: 로그인 버튼 클릭
    SPA->>AS: GET /oauth2/authorize<br/>?client_id=...&scope=openid profile
    AS->>SPA: 302 → /login (SavedRequest 저장)
    SPA->>AS: GET /login
    AS->>SPA: 로그인 페이지 (Form + Google 버튼)
    User->>AS: Google 로그인 클릭
    AS->>Google: GET /oauth2/authorization/google
    Google->>AS: 콜백 /login/oauth2/code/google?code=...
    AS->>Google: 사용자 정보 요청
    Google->>AS: email, name, sub 반환
    AS->>DB: SocialAccount 조회/생성<br/>User 조회/생성 (SocialOAuth2UserService)
    AS->>Redis: 세션 저장 (Spring Session, 1시간)
    AS->>AS: JsonAuthenticationSuccessHandler<br/>SavedRequest 복원 → /oauth2/authorize 재처리
    AS->>SPA: 302 → /callback?code=<인가코드>
    SPA->>AS: POST /oauth2/token<br/>grant_type=authorization_code&code=...
    Note over AS: oauth2_authorization InMemory 저장
    AS->>SPA: access_token + refresh_token
```

### 3. 이메일/비밀번호 회원가입

> ⚠️ 이메일 인증(`POST /api/v1/users/verify-email`)은 미구현 상태입니다. Redis 토큰 저장 및 발송 코드가 주석 처리되어 있어 항상 `T001 INVALID_TOKEN` 에러를 반환합니다.

```mermaid
sequenceDiagram
    actor User as 사용자
    participant API as /api/v1/users
    participant DB as PostgreSQL

    User->>API: POST /signup<br/>{email, password, nickname}
    API->>DB: 이메일 중복 확인
    API->>DB: User 저장 (emailVerified=false, ROLE_USER 부여)
    API->>User: 201 Created
```

---

## API 명세

### 공개 엔드포인트 (인증 불필요)

| 메서드 | 경로 | 설명 |
|---|---|---|
| `POST` | `/api/v1/users/signup` | 회원가입 |
| `GET` | `/actuator/health` | 헬스 체크 |
| `GET` | `/actuator/info` | 앱 정보 |

### 인증 필요 엔드포인트 (Bearer JWT)

| 메서드 | 경로 | 권한 | 설명 |
|---|---|---|---|
| `POST` | `/api/v1/users/verify-email` | JWT 필요 | 이메일 인증 토큰 확인 |
| `GET` | `/api/v1/users/me` | `ROLE_USER` | 내 정보 조회 |
| `PATCH` | `/api/v1/users/me` | `ROLE_USER` | 닉네임 수정 |
| `DELETE` | `/api/v1/users/me` | `ROLE_USER` | 회원 탈퇴 |

### Authorization Server 엔드포인트 (Spring 표준)

| 경로 | 설명 |
|---|---|
| `GET /oauth2/authorize` | 인가 요청 |
| `POST /oauth2/token` | 토큰 발급 / 갱신 |
| `GET /oauth2/jwks` | JWK 공개키 |
| `GET /.well-known/openid-configuration` | OIDC Discovery |
| `POST /oauth2/revoke` | 토큰 폐기 |

### 개발 도구

| 경로 | 설명 |
|---|---|
| `/swagger-ui.html` | API 문서 |
| `/h2-console` | DB 콘솔 (local 프로파일) |
| `/actuator/prometheus` | Prometheus 메트릭 |

---

## 로컬 실행 방법

### 사전 조건

```bash
# Redis 실행
docker run -d -p 6379:6379 redis
```

소셜 로그인을 사용하려면 각 플랫폼에서 OAuth2 앱을 등록하고 콜백 URI를 추가해야 합니다.

| 제공자 | 콜백 URI |
|---|---|
| Google | `http://localhost:8080/login/oauth2/code/google` |

### 환경변수 설정 (선택 — 소셜 로그인 필요 시)

```bash
export GOOGLE_CLIENT_ID=<Google Cloud Console 발급>
export GOOGLE_CLIENT_SECRET=<Google Cloud Console 발급>
```

### 실행

```bash
# 빌드
./gradlew build

# 로컬 실행
./gradlew bootRun --args='--spring.profiles.active=local'

# 테스트
./gradlew test
```

### 접속 정보

| 항목 | 주소 |
|---|---|
| API 문서 | http://localhost:8080/swagger-ui.html |
| H2 콘솔 | http://localhost:8080/h2-console |
| OIDC Discovery | http://localhost:8080/.well-known/openid-configuration |
| 헬스 체크 | http://localhost:8080/actuator/health |
