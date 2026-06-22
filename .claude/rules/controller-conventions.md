# Controller 규칙

이 파일은 Controller 작성 시 항상 따라야 할 규칙을 정의한다.

---

## @RestController 기본 구조

클래스 선언부에 `@RestController`, `@RequestMapping`, `@RequiredArgsConstructor` 세 어노테이션을 함께 사용한다.
의존성은 `private final` 필드로만 선언한다.

```java
@RestController
@RequestMapping("/api/v1/users")
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    @GetMapping("/{id}")
    public ResponseEntity<ApiResponse<UserResponse>> getUser(@PathVariable Long id) {
        return ResponseEntity.ok(ApiResponse.ok(userService.findById(id)));
    }
}
```

```java
// ❌ 잘못된 예
@Controller                          // @ResponseBody 없이 사용
@RequestMapping("/api/v1/users")
public class UserController {

    @Autowired                       // 필드 주입 금지
    private UserService userService;

    @GetMapping("/{id}")
    public User getUser(@PathVariable Long id) {   // Entity 직접 반환
        return userRepository.findById(id).get();  // Repository 직접 호출
    }
}
```

---

## @Controller — HTML 폼 페이지

HTML 뷰를 반환하거나 `@ModelAttribute`로 폼을 바인딩할 때는 `@Controller`를 사용한다.
`@RestController`와 혼용하지 않는다.

```java
// ✅ 올바른 예 — HTML 로그인 페이지
@Controller
@RequiredArgsConstructor
public class LoginController {

    @GetMapping("/login")
    public String loginPage(Model model) {
        return "login";     // templates/login.html 렌더링
    }
}

// ✅ 올바른 예 — @ModelAttribute 폼 바인딩
@Controller
@RequiredArgsConstructor
public class SignUpController {

    @PostMapping("/signup")
    public String signUp(@ModelAttribute SignUpRequest request) {
        userService.signUp(request);
        return "redirect:/login";
    }
}
```

---

## API 경로 버저닝 규칙

| 경로 유형 | 패턴 | 예시 |
|-----------|------|------|
| REST API | `/api/v{N}/` | `/api/v1/users`, `/api/v1/clients` |
| HTML 폼 | 버전 없음 | `/login`, `/signup` |
| OAuth2 엔드포인트 | 프레임워크 기본 경로 | `/oauth2/authorize`, `/.well-known/jwks.json` |

새 REST API를 추가할 때는 반드시 `/api/v1/` 접두사를 사용한다.

---

## Content-Type 인식 응답 (Handler)

`Accept: application/json` 요청에는 JSON 응답, 그 외에는 HTML 리다이렉트로 응답한다.
이 분기는 Security Handler (`AuthenticationSuccessHandler`, `AuthenticationFailureHandler` 등)에서 사용한다.

```java
// ✅ 올바른 예
String accept = request.getHeader(HttpHeaders.ACCEPT);
if (accept != null && accept.contains(MediaType.APPLICATION_JSON_VALUE)) {
    response.setContentType(MediaType.APPLICATION_JSON_VALUE);
    // JSON 응답 작성
} else {
    response.sendRedirect("/login?error=true");
}

// ❌ 잘못된 예
// Accept 헤더를 무시하고 항상 리다이렉트 — API 클라이언트 호환 불가
response.sendRedirect("/login?error=true");
```
