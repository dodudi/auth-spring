# 작업 히스토리

## 2026-05-20

---

### 1. Client Credentials 토큰 요청 방법

**문제**
Client Credentials 플로우로 `/oauth2/token`에 요청하는 방법을 몰랐음.

**원인**
클라이언트가 `CLIENT_SECRET_BASIC` 인증 방식으로 등록되어 있어 자격증명을 Body가 아닌 `Authorization: Basic` 헤더로 전송해야 함.

**해결 방법**
```bash
curl -X POST https://auth.rudy.it.kr/oauth2/token \
  -H "Authorization: Basic $(echo -n 'clientId:clientSecret' | base64)" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials&scope=read"
```

**결과**
토큰 정상 발급 확인.

---

### 2. CORS 오류 — Authorization Server 엔드포인트

**문제**
브라우저에서 `https://auth.rudy.it.kr/oauth2/token` 요청 시 CORS 오류 발생.
```
No 'Access-Control-Allow-Origin' header is present on the requested resource.
```

**원인**
- 1차: 요청 URL이 `http://`여서 nginx가 301(HTTP → HTTPS)로 리다이렉트. 리다이렉트 응답에 CORS 헤더 없음.
- 2차: `/oauth2/token`은 `@Order(1)`인 `authorizationServerSecurityFilterChain`이 먼저 처리하는데, 해당 체인에 `.cors()` 설정이 없었음. `SecurityConfig`의 CORS 빈이 적용되지 않음.

**해결 방법**
1. 프론트 요청 URL을 `https://`로 변경 (301 문제 해결)
2. `AuthorizationServerConfig.authorizationServerSecurityFilterChain`에 `.cors(cors -> cors.configurationSource(corsConfigurationSource))` 추가

**결과**
PR #1 머지. CORS 헤더 정상 응답 확인.

---

### 3. Issuer URI 오류 — `iss` 클레임이 `http://`로 발급

**문제**
발급된 JWT의 `iss` 클레임이 `https://auth.rudy.it.kr`이 아닌 `http://auth.rudy.it.kr`로 나옴.
환경변수 `AUTH_ISSUER_URI=https://auth.rudy.it.kr`이 설정되어 있음에도 반영 안 됨.

**원인**
`AuthorizationServerSettings`에 issuer를 명시하지 않아 Spring이 요청 URL 기반으로 자동 추론함.
내부적으로 `http://`로 들어오는 요청(nginx → 컨테이너 통신)을 기준으로 결정되어 `http://`가 노출됨.

**해결 방법**
1. (단순) `AuthorizationServerSettings.builder().issuer(issuerUri).build()`에 `@Value`로 직접 주입
2. (채택) `RsaProperty`와 동일한 패턴으로 `AuthProperty` 클래스를 `security/property` 패키지에 생성 후 생성자 주입으로 관리

**결과**
PR #2 머지. `iss` 클레임이 `https://auth.rudy.it.kr`로 정상 발급.
`/.well-known/openid-configuration`의 `issuer`도 동일하게 확인 가능.

---

### 4. 코드 리뷰 — AuthorizationServerConfig 권고사항 반영

**문제 (권고)**
1. `@Value` 필드 주입과 `@RequiredArgsConstructor` 혼용 — `issuerUri`가 Lombok 생성자에 포함되지 않아 테스트 시 주입 불가
2. `jwtTokenCustomizer`가 Client Credentials 토큰 발급 시에도 `userRepository.findByEmail(clientId)` DB 조회 실행 — 항상 empty 반환하는 불필요한 쿼리

**해결 방법**
1. `AuthProperty` 클래스로 분리하여 생성자 주입으로 전환 (3번 작업에서 함께 반영, `security/property` 패키지)
2. `context.getAuthorizationGrantType().equals(AuthorizationGrantType.CLIENT_CREDENTIALS)` 분기 추가하여 DB 조회 스킵

**결과**
불필요한 DB 조회 제거. Property 관리 일관성 확보.
