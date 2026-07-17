# 예외 · ErrorCode 규칙

이 파일은 예외 처리와 에러 코드 작성 시 항상 따라야 할 규칙을 정의한다.

---

## ErrorCode 도메인 접두사

| 접두사 | 도메인 | 예시 |
|--------|--------|------|
| `C` | Common (공통) | `C001`, `C002` |
| `U` | User (사용자) | `U001`, `U002` |
| `CL` | Client (OAuth2 클라이언트) | `CL001`, `CL002` |
| `T` | Token (토큰) | `T001`, `T002` |

새 도메인을 추가할 때는 2자리 이내 영문 접두사를 먼저 이 표에 정의한 뒤 코드를 추가한다.
접두사 내 번호는 001부터 순차 증가한다. 삭제된 번호는 재사용하지 않는다.

### 현재 등록된 ErrorCode 목록

| 코드 | 이름 | HTTP 상태 | 설명 |
|------|------|-----------|------|
| `C001` | `INVALID_INPUT` | 400 | 유효하지 않은 입력값 |
| `C002` | `INTERNAL_SERVER_ERROR` | 500 | 서버 내부 오류 |
| `C003` | `UNAUTHORIZED` | 401 | 인증 필요 |
| `C004` | `FORBIDDEN` | 403 | 권한 없음 |
| `C005` | `IP_BLOCKED` | 429 | IP 차단 (로그인 시도 초과) |
| `U001` | `USER_NOT_FOUND` | 404 | 사용자를 찾을 수 없음 |
| `U002` | `EMAIL_ALREADY_EXISTS` | 409 | 이미 사용 중인 이메일 |
| `U003` | `INVALID_PASSWORD` | 400 | 잘못된 비밀번호 |
| `U004` | *(결번 — 이메일 인증 기능 제거로 삭제됨, 재사용 금지)* | - | - |
| `U005` | `ACCOUNT_SUSPENDED` | 403 | 정지된 계정 |
| `U006` | `ACCOUNT_WITHDRAWN` | 403 | 탈퇴한 계정 |
| `U007` | `ACCOUNT_LOCKED` | 423 | 잠긴 계정 (로그인 실패 초과) |
| `U008` | `INVALID_CREDENTIALS` | 401 | 이메일 또는 비밀번호 불일치 |
| `CL001` | `CLIENT_NOT_FOUND` | 404 | OAuth2 클라이언트를 찾을 수 없음 |
| `CL002` | `CLIENT_ID_ALREADY_EXISTS` | 409 | 이미 사용 중인 클라이언트 ID |
| `T001` | `INVALID_TOKEN` | 401 | 유효하지 않은 토큰 |
| `T002` | `TOKEN_EXPIRED` | 401 | 만료된 토큰 |

새 ErrorCode를 추가하기 전에 위 목록에서 재사용 가능한 코드가 있는지 먼저 확인한다.

```java
// ✅ 올바른 예
PAYMENT_NOT_FOUND(HttpStatus.NOT_FOUND, "P001", "결제 내역을 찾을 수 없습니다."),

// ❌ 잘못된 예
PAYMENT_NOT_FOUND(HttpStatus.NOT_FOUND, "payment_not_found", "결제 내역을 찾을 수 없습니다."),  // 접두사 규칙 미준수
PAYMENT_NOT_FOUND(HttpStatus.NOT_FOUND, "U010", "결제 내역을 찾을 수 없습니다."),              // 도메인 불일치
```

---

## AuthException 사용 규칙

모든 비즈니스 예외는 `AuthException(ErrorCode)`로 던진다.
`RuntimeException`을 직접 throw하거나 문자열 메시지로 예외를 생성하지 않는다.

```java
// ✅ 올바른 예
throw new AuthException(ErrorCode.USER_NOT_FOUND);

// ❌ 잘못된 예
throw new RuntimeException("사용자를 찾을 수 없습니다.");   // RuntimeException 직접 사용
throw new AuthException("사용자를 찾을 수 없습니다.");      // 문자열 생성자 없음 — 컴파일 오류
```

`AuthException`에 생성자를 추가하지 않는다. `ErrorCode`가 메시지를 관리한다.

---

## 응답 형식

### 성공 응답

```java
// 조회
return ResponseEntity.ok(ApiResponse.ok(data));

// 생성
URI location = URI.create("/api/v1/users/" + response.id());
return ResponseEntity.created(location).body(ApiResponse.ok(response));

// 삭제
return ResponseEntity.noContent().build();
```

### 실패 응답

`ApiResponse<Void>`를 사용한다. `ErrorResponse` 클래스는 존재하지 않는다.

```java
// GlobalExceptionHandler 내부
return ResponseEntity
        .status(e.getErrorCode().getHttpStatus())
        .body(ApiResponse.fail(e.getErrorCode()));

// 메시지를 덮어써야 할 때 (Validation 등)
return ResponseEntity
        .status(ErrorCode.INVALID_INPUT.getHttpStatus())
        .body(ApiResponse.fail(ErrorCode.INVALID_INPUT, "필드명: 상세 메시지"));
```

실패 응답 JSON 형식:
```json
{
  "code": "U001",
  "message": "사용자를 찾을 수 없습니다.",
  "data": null
}
```

---

## GlobalExceptionHandler 위치 및 구조

`GlobalExceptionHandler`는 `common/exception` 패키지에 위치한다.
(`api` 패키지가 아님에 주의)

```
com.auth.common.exception/
├── AuthException.java
├── ErrorCode.java
└── GlobalExceptionHandler.java   ← 여기
```

처리 핸들러 우선순위:

| 순서 | 대상 | 로그 레벨 |
|------|------|-----------|
| 1 | `AuthException` | `WARN` |
| 2 | `MethodArgumentNotValidException` | `WARN` |
| 3 | `NoResourceFoundException` | `DEBUG` |
| 4 | `Exception` (fallback) | `ERROR` |

새 예외 타입을 핸들러에 추가할 때는 위 순서표를 함께 갱신한다.
`Exception` fallback 핸들러보다 구체적인 타입을 항상 위에 배치한다.

```java
// ✅ 올바른 예 — 구체 타입 핸들러 추가
@ExceptionHandler(PaymentException.class)
public ResponseEntity<ApiResponse<Void>> handlePaymentException(PaymentException e) {
    log.warn("PaymentException: {}", e.getMessage());
    return ResponseEntity
            .status(e.getErrorCode().getHttpStatus())
            .body(ApiResponse.fail(e.getErrorCode()));
}

// ❌ 잘못된 예
// - Controller마다 try-catch로 예외 처리
// - Exception 타입으로 직접 catch해서 응답 생성
// - 스택 트레이스를 응답 바디에 포함
```
