# 디렉토리 구조 규칙

이 파일은 패키지 및 디렉토리 구조 작성 시 항상 따라야 할 규칙을 정의한다.

---

## 원칙 — 기능적 응집도 우선

패키지는 기술적 역할이 아닌 기능 도메인을 기준으로 나눈다.
"이 파일을 수정할 때 함께 수정하게 될 파일들이 같은 패키지에 있는가?"를 기준으로 판단한다.

```
// ✅ 올바른 예 — 도메인별로 설정 포함
com.auth.security.config.SecurityConfig
com.auth.admin.config.AdminSecurityConfig

// ❌ 잘못된 예 — 기술적 역할 버킷
com.auth.config.SecurityConfig
com.auth.config.AdminSecurityConfig
```

---

## 전체 패키지 구조 (예시)

```
com.example/
├── ExampleApplication.java
│
├── common/                        도메인에 속하지 않는 공유 코드
│   ├── config/                    인프라 공통 설정 (JPA Auditing 등)
│   ├── exception/                 CustomException, ErrorCode, GlobalExceptionHandler
│   ├── filter/                    RequestLoggingFilter
│   ├── init/                      ApplicationRunner 기반 초기화 클래스 (프로파일별)
│   ├── response/                  ApiResponse
│   └── util/                      정적 유틸 클래스
│
├── order/                         주문 도메인
│   ├── domain/                    Entity, Repository, Enum
│   ├── application/               Service (비즈니스 로직)
│   ├── api/                       Controller
│   └── dto/                       Request / Response 레코드
│
├── payment/                       결제 도메인
│   ├── config/                    도메인 전용 설정
│   ├── domain/                    Repository 인터페이스
│   │   └── support/               Repository 커스텀 구현체
│   ├── application/               Service 인터페이스 + 구현체
│   ├── api/                       Controller
│   └── dto/                       Request / Response 레코드
│
└── notification/                  알림 도메인
    ├── config/                    도메인 전용 설정
    ├── property/                  외부 설정값 바인딩 클래스
    ├── application/               Service
    ├── handler/                   이벤트 핸들러
    └── api/                       Controller
```

---

## 도메인 내부 서브패키지 규칙

| 서브패키지 | 포함 대상 | 비고 |
|-----------|----------|------|
| `domain/` | Entity, Repository 인터페이스, Enum | JPA 영속성 경계 |
| `domain/support/` | Repository 커스텀 구현체 | JPA 커스텀 구현체 및 순수 JDBC 구현체 모두 포함 |
| `application/` | Service 인터페이스·구현체 | 비즈니스 로직 |
| `api/` | Controller | HTTP 요청·응답 처리 |
| `dto/` | Request·Response 레코드 | 레이어 간 데이터 전달 |
| `config/` | `@Configuration` 클래스 | 해당 도메인 설정만 포함 |
| `property/` | `@ConfigurationProperties` 클래스 | 외부 설정값 바인딩 |
| `handler/` | 이벤트·예외 핸들러 | |
| `filter/` | `OncePerRequestFilter` 구현체 | 해당 도메인 전용 필터 |

---

## 설정 클래스 위치 규칙

설정 클래스는 중앙 `config/` 패키지에 모으지 않고 해당 도메인 하위 `config/`에 둔다.
특정 도메인에 속하지 않는 인프라 설정(JPA Auditing 등)은 `common/config/`에 둔다.

---

## 인터페이스·구현체 위치 규칙

Repository 인터페이스는 `domain/`에, 커스텀 구현체는 `domain/support/`에 둔다.

```
payment/domain/
├── OrderRepository.java           ← 인터페이스
└── support/
    └── OrderRepositoryImpl.java   ← 커스텀 구현체 (JPA 또는 JDBC)
```

**Spring Data JPA 커스텀 구현체** (`JpaRepository`를 확장하는 인터페이스의 추가 쿼리)는 Spring이 `{Interface}Impl` 명명 규칙으로 자동 연결한다.

**순수 JDBC 구현체** (`JpaRepository`를 상속하지 않는 인터페이스)는 `domain/support/`에 위치하지만 Spring이 자동 연결하지 않으므로 직접 `@Component` 또는 `@Bean`으로 등록한다.

```java
// ✅ 순수 JDBC Repository — 명시적 빈 등록 필요
// client/domain/ClientRepository.java
public interface ClientRepository {
    List<ClientSummary> findAll();
    void deleteById(String id);
}

// client/domain/support/ClientRepositoryImpl.java
@Repository                      // @Component 또는 @Repository로 직접 등록
@RequiredArgsConstructor
public class ClientRepositoryImpl implements ClientRepository {
    private final JdbcTemplate jdbcTemplate;
    ...
}
```

Service 인터페이스와 구현체는 같은 `application/` 패키지에 둔다.

```
payment/application/
├── PaymentService.java            ← 인터페이스
└── SimplePaymentService.java      ← 구현체
```

---

## 금지 사항

```
// ❌ impl/ 패키지 사용 금지
com.example.payment.application.impl.SimplePaymentService

// ❌ 중앙 config/ 패키지 금지
com.example.config.SecurityConfig
com.example.config.PaymentConfig

// ❌ 기술적 분류 패키지 금지
com.example.interfaces/
com.example.services/
com.example.repositories/
```

---

## ApplicationRunner 초기화 클래스 위치

프로파일별 데이터 초기화 클래스는 `common/init/`에 위치시킨다.
`@Profile` 어노테이션으로 실행 환경을 제한한다.

```java
// ✅ 올바른 예
// common/init/LocalDataInitializer.java
@Component
@Profile("local")
@RequiredArgsConstructor
public class LocalDataInitializer implements ApplicationRunner {

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        // 로컬 테스트 데이터 생성
    }
}
```

---

## 새 도메인 추가 시 체크리스트

1. 루트 하위에 도메인명 패키지 생성 (`com.example.{domain}/`)
2. 필요한 서브패키지만 생성 — 비어 있는 패키지는 만들지 않는다
3. 도메인 전용 설정이 있으면 `{domain}/config/`에 배치
4. 다른 도메인에서 참조하는 공유 코드는 `common/`으로 이동
