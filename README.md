# auth-spring

Spring Boot 기반 OAuth2 인증 서버. Google 소셜 로그인을 지원하며, Authorization Code 흐름을 제공합니다.

## 목차
1. [분리된 Security Filter Chain로 이동](#분리된-security-filter-chain)  
2. [Spring Session + Redis 구현으로 인증 서버 세션 공유](#spring-session--redis-구현으로-인증-서버-세션-공유)  
3. [JWT + RSA 비대칭키](#JWT--RSA-비대칭키)  
4. [Admin 관리 페이지를 통한 Client 관리](#admin-관리-페이지를-통한-client-관리)  
---

## 분리된 Security Filter Chain
문제: 하나의 FilterChain 에서 모든 요청을 처리하여 코드가 복잡해지는 문제  
해결: FilterChain을 기능으로 분리하여 각자 처리해야할 요청 경로를 지정해서 처리하도록 구현

### Authorization Server 필터 체인 설정
- 해당 필터가 특정 경로의 요청을 처리할 수 있도록 securityMatcher 설정을 합니다.
- OIDC 설정으로 ID Token을 발급 받을 수 있도록 설정합니다.
- Access Token의 경우 권한 부여 정보를 담는 JWT 입니다.
- ID Token의 경우 사용자의 신원을 확인할 수 있는 정보를 담는 JWT 입니다.
```java
@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    // .. 생략

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            RegisteredClientRepository registeredClientRepository) {
        http
                .oauth2AuthorizationServer(authorizationServer -> {
                    http.securityMatcher(authorizationServer.getEndpointsMatcher());
                    authorizationServer.oidc(Customizer.withDefaults());
                    authorizationServer.authorizationEndpoint(endpoint -> endpoint.errorResponseHandler(customAuthorizationServerFailureHandler));
                })
                .authorizeHttpRequests(authorize -> authorize
                        .anyRequest().authenticated()
                )
                .exceptionHandling(exceptions -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new ClientAwareLoginUrlAuthenticationEntryPoint(registeredClientRepository),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                );

        return http.build();
    }

    // ... 생략
}
```
<img width="667" height="277" alt="image" src="https://github.com/user-attachments/assets/fd479a8e-37ec-4877-ad3a-ff55593c2e87" />

### Admin 필터 체인 설정
```java
@Configuration
public class AdminSecurityConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain adminSecurityFilterChain(HttpSecurity http) {
        http
                .securityMatcher("/admin/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/admin/login").permitAll()
                        .anyRequest().hasRole("ADMIN")
                )
                .formLogin(form -> form
                        .loginPage("/admin/login")
                        .loginProcessingUrl("/admin/login")
                        .defaultSuccessUrl("/admin/clients", true)
                        .failureUrl("/admin/login?error=true")
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/admin/logout")
                        .logoutSuccessUrl("/admin/login?logout=true")
                )
                .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));

        return http.build();
    }

}
```
<img width="652" height="290" alt="image" src="https://github.com/user-attachments/assets/117fce93-503a-49a1-96b3-ba7a0f0e67ef" />

### Resource Server 필터 체인
```java
@Configuration
@EnableMethodSecurity
public class ResourceServerConfig {

    @Bean
    @Order(3)
    public SecurityFilterChain resourceServerSecurityFilterChain(HttpSecurity http, CorsConfigurationSource corsConfigurationSource) throws Exception {
        http
                .securityMatcher("/api/**")
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers("/api/v1/users/signup").permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(AbstractHttpConfigurer::disable)
                .oauth2ResourceServer((oauth2) -> oauth2
                        .jwt((jwt) -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                );

        return http.build();
    }

    // ... 생략
}
```
<img width="951" height="298" alt="image" src="https://github.com/user-attachments/assets/22db7561-58ef-4d9a-b0fe-1e64338625f3" />

### 나머지 처리 필터 체인
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${auth.allowed-origins}")
    private String allowedOrigins;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Order(4)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, SocialOAuth2UserService socialOAuth2UserService, ObjectMapper objectMapper) throws Exception {
        JsonAuthenticationSuccessHandler successHandler = new JsonAuthenticationSuccessHandler(objectMapper);
        JsonAuthenticationFailureHandler failureHandler = new JsonAuthenticationFailureHandler(objectMapper);

        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/oauth/error").permitAll()
                        .anyRequest().authenticated()
                )
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .successHandler(successHandler)
                        .failureHandler(failureHandler)
                        .permitAll()
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .successHandler(successHandler)
                        .failureHandler(failureHandler)
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(socialOAuth2UserService)
                        )
                );

        return http.build();
    }

    // ... 생략
}
```
<img width="794" height="318" alt="image" src="https://github.com/user-attachments/assets/085e3c2e-5af6-4024-9260-2310e328f248" />

## Spring Session + Redis 구현으로 인증 서버 세션 공유
문제: 하나의 인스턴스로 실행 중인 인증 서버에 장애가 발생할 경우 인증 서버를 사용하는 모든 서비스에 문제가 발생합니다.  
해결: 다중 인스턴스 간 세션 상태를 공유하여 동일한 세션 상태를 유지할 수 있도록 구현했습니다.
```java
@Configuration
@EnableRedisHttpSession(redisNamespace = "spring:session:auth", maxInactiveIntervalInSeconds = 3600)
public class SessionConfig implements BeanClassLoaderAware {

    private ClassLoader loader;

    @Bean
    public RedisSerializer<Object> springSessionDefaultRedisSerializer() {
        return new JacksonJsonRedisSerializer<>(createJsonMapper(), Object.class);
    }

    private static JsonMapper createJsonMapper() {
        BasicPolymorphicTypeValidator.Builder builder = BasicPolymorphicTypeValidator.builder()
                .allowIfBaseType(Object.class)
                .allowIfSubType("java.util.concurrent.")
                .allowIfSubType("java.util.")
                .allowIfSubType("org.springframework.security.")
                .allowIfSubType("org.springframework.session.");

        OAuth2AuthorizationServerJacksonModule authorizationServerJacksonModule = new OAuth2AuthorizationServerJacksonModule();
        authorizationServerJacksonModule.configurePolymorphicTypeValidator(builder);
        List<JacksonModule> securityJacksonModules = SecurityJacksonModules.getModules(JdbcOAuth2AuthorizationService.class.getClassLoader(), builder);
        return JsonMapper.builder()
                .addModules(authorizationServerJacksonModule)
                .addModules(securityJacksonModules)
                .build();
    }

    @Override
    public void setBeanClassLoader(@NonNull ClassLoader classLoader) {
        this.loader = classLoader;
    }
}
```

## JWT + RSA 비대칭키
문제: 인증 서버를 사용하기 위한 외부 서비스가 JWT 토큰 검증을 위한 비밀키를 설정해야 합니다. 이는 보안상 위험하다고 판단했습니다.
해결: RSA 비대칭키 방식을 사용하여 개인키를 인증 서버에 설정하고, 공개키는 개인키로 서명된 값을 검증하고, `/oauth2/jwks` 요청으로 공개키 확인을 하도록 구현했습니다.
```java
@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private final RsaProperty rsaProperty;

    // .. 생략

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = new RSAKey.Builder(rsaProperty.getPublicKey())
                .privateKey(rsaProperty.getPrivateKey())
                .keyID("auth-server-key")
                .build();
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    // .. 생략
}
```

## Admin 관리 페이지를 통한 Client 관리
문제: 서비스를 생성할 때마다 클라이언트 정보를 등록하고 관리해야 한다는 불편함이 존재합니다.
해결: 관리자 페이지를 통해서 `Client ID`, `Client Secret`, `Redirect URI`, `PKCE 여부`, `Grant Type`, `Token TTL` 등 다양한 정보를 쉽게 관리하도록 구현했습니다.  
- Client Secret 은 즉시 재발급 가능하도록 구현했으며, 기존 키는 무효화되어 해당 외부 서비스는 새롭게 발급된 키로 교체해야 합니다.
```java
@Configuration
public class AdminSecurityConfig {

    @Bean
    @Order(2)
    public SecurityFilterChain adminSecurityFilterChain(HttpSecurity http) {
        http
                .securityMatcher("/admin/**")
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/admin/login").permitAll()
                        .anyRequest().hasRole("ADMIN")
                )
                .formLogin(form -> form
                        .loginPage("/admin/login")
                        .loginProcessingUrl("/admin/login")
                        .defaultSuccessUrl("/admin/clients", true)
                        .failureUrl("/admin/login?error=true")
                        .permitAll()
                )
                .logout(logout -> logout
                        .logoutUrl("/admin/logout")
                        .logoutSuccessUrl("/admin/login?logout=true")
                )
                .csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));

        return http.build();
    }

}
```
