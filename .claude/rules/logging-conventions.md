# 로깅 규칙

이 파일은 로그 작성 시 항상 따라야 할 규칙을 정의한다.

---

## 로그 형식

비즈니스 이벤트 로그는 구조화된 태그를 포함한다.

```java
// ✅ 올바른 예
log.info("[USER_SIGNUP] email={}", user.getEmail());
log.info("[LOGIN_SUCCESS] email={}", email);
log.warn("[LOGIN_FAILURE] email={}", email);

// ❌ 잘못된 예
log.info("유저가 가입했습니다: " + user.getEmail());   // 태그 없음, 문자열 연산
log.info("signup success");                            // 식별 불가
```

### 기존 로그 태그 목록

새 태그를 추가하기 전에 아래 목록에서 재사용 가능한 태그가 있는지 확인한다.

| 태그 | 레벨 | 설명 |
|------|------|------|
| `[LOGIN_SUCCESS]` | INFO | 로그인 성공 |
| `[LOGIN_FAILURE]` | WARN | 로그인 실패 |
| `[LOGIN_ATTEMPT]` | WARN | 로그인 시도 횟수 기록 (Redis) |
| `[USER_SIGNUP]` | INFO | 회원 가입 완료 |
| `[USER_WITHDRAW]` | INFO | 회원 탈퇴 완료 |
| `[SOCIAL_LOGIN]` | INFO | 소셜 로그인 처리 |
| `[RATE_LIMIT]` | WARN | 로그인 시도 횟수 초과 차단 |

---

## 로그 레벨 기준

| 레벨 | 기준 |
|------|------|
| `ERROR` | 복구 불가능한 장애 (DB 연결 실패 등) |
| `WARN` | 예상 가능한 비즈니스 예외 (인증 실패, 리소스 없음) |
| `INFO` | 비즈니스 이벤트 (가입, 로그인, 탈퇴) |
| `DEBUG` | 개발 디버깅 전용 — 운영 로그에 남기지 않는다 |

---

## MDC traceId

MDC `traceId`는 `RequestLoggingFilter`가 자동 주입하므로 직접 `MDC.put("traceId", ...)`를 호출하지 않는다.

`RequestLoggingFilter`가 관리하는 MDC 키와 응답 헤더:

| 항목 | 값 | 설명 |
|------|-----|------|
| MDC 키 `traceId` | UUID | 요청마다 새로 생성 |
| MDC 키 `method` | HTTP 메서드 | GET, POST 등 |
| MDC 키 `uri` | 요청 URI | 경로만 포함 |
| 응답 헤더 `X-Trace-Id` | `traceId`와 동일 | 클라이언트 측 추적용 |

`/actuator/**`, `/swagger-ui/**`, `/v3/api-docs/**` 경로는 필터에서 제외된다.

---

## Redis 장애 시 Warn 로그 패턴

Redis에 의존하는 기능(레이트 리밋, 세션 등)은 Redis 장애 시 `WARN`으로 기록하고 **fail-open** 처리한다.
예외를 상위로 전파하지 않으며, 서비스를 중단시키지 않는다.

```java
// ✅ 올바른 예
try {
    return redisTemplate.execute(...);
} catch (Exception e) {
    log.warn("[LOGIN_ATTEMPT] Redis 장애로 차단 여부 확인 불가, 통과 처리: {}", e.getMessage());
    return false;   // fail-open
}

// ❌ 잘못된 예
// Redis 예외를 그대로 전파 — 인증 흐름 전체 중단
Long count = redisTemplate.execute(...);
```
