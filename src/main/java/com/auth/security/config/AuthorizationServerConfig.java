package com.auth.security.config;

import com.auth.security.application.TokenRevocationService;
import com.auth.security.handler.ClientAwareLoginUrlAuthenticationEntryPoint;
import com.auth.security.handler.CustomAuthorizationServerFailureHandler;
import com.auth.security.property.AuthProperty;
import com.auth.security.property.RsaProperty;
import com.auth.user.repository.UserRepository;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfigurationSource;

import java.time.Instant;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private final RsaProperty rsaProperty;
    private final AuthProperty authProperty;
    private final CustomAuthorizationServerFailureHandler customAuthorizationServerFailureHandler;
    private final CorsConfigurationSource corsConfigurationSource;

    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http,
            RegisteredClientRepository registeredClientRepository) {
        http
                .cors(cors -> cors.configurationSource(corsConfigurationSource))
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

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    public OAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public OAuth2AuthorizationConsentService authorizationConsentService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        RSAKey rsaKey = new RSAKey.Builder(rsaProperty.getPublicKey())
                .privateKey(rsaProperty.getPrivateKey())
                .keyID("auth-server-key")
                .build();
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    // 정지·탈퇴로 폐기된 사용자의 토큰을 만료 전에도 거부한다 (TokenRevocationService 기록 시각 이후 발급된 토큰만 유효)
    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource, TokenRevocationService tokenRevocationService) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSource(jwkSource).build();

        OAuth2TokenValidator<Jwt> revocationValidator = jwt -> {
            UUID userId;
            try {
                userId = UUID.fromString(jwt.getSubject());
            } catch (IllegalArgumentException e) {
                // client_credentials 토큰 등 사용자와 연결되지 않은 subject는 검사 대상이 아니다
                return OAuth2TokenValidatorResult.success();
            }

            if (tokenRevocationService.isRevoked(userId, jwt.getIssuedAt())) {
                return OAuth2TokenValidatorResult.failure(
                        new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, "폐기된 사용자의 토큰입니다.", null));
            }
            return OAuth2TokenValidatorResult.success();
        };

        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(JwtValidators.createDefault(), revocationValidator));
        return decoder;
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(authProperty.getIssuerUri())
                .build();
    }

    // Access Token에 사용자 roles, email을 포함시킨다 (sub는 UUID로 자동 설정됨)
    // client_credentials 토큰은 사용자 정보가 없으므로 건너뛴다
    // 세션 재사용(SSO)이나 refresh_token 재발급은 로그인 시점의 계정 상태 검사를 거치지 않으므로,
    // 토큰을 새로 발급하는 시점마다 폐기 여부를 다시 확인한다
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtTokenCustomizer(UserRepository userRepository, TokenRevocationService tokenRevocationService) {
        return context -> {
            if (!OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
                return;
            }
            if (AuthorizationGrantType.CLIENT_CREDENTIALS.equals(context.getAuthorizationGrantType())) {
                return;
            }

            Authentication principal = context.getPrincipal();
            String principalName = principal.getName();
            UUID userId = UUID.fromString(principalName);

            if (tokenRevocationService.isRevoked(userId, Instant.now())) {
                throw new OAuth2AuthenticationException(
                        new OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "폐기된 사용자입니다.", null));
            }

            Set<String> roles = principal.getAuthorities().stream()
                    .map(GrantedAuthority::getAuthority)
                    .collect(Collectors.toSet());
            context.getClaims().claim("roles", roles);

            log.debug("[TOKEN_CUSTOMIZER] principalName={} principalType={}", principalName, principal.getClass().getSimpleName());
            userRepository.findById(userId)
                    .ifPresentOrElse(
                            user -> context.getClaims().claim("email", user.getEmail()),
                            () -> log.warn("[TOKEN_CUSTOMIZER] user not found for userId={}", userId)
                    );
        };
    }
}
