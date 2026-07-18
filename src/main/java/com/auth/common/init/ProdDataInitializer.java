package com.auth.common.init;

import com.auth.user.domain.Role;
import com.auth.user.domain.User;
import com.auth.user.repository.RoleRepository;
import com.auth.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.UUID;

@Slf4j
@Component
@Profile("prod")
@RequiredArgsConstructor
public class ProdDataInitializer implements ApplicationRunner {

    private static final String ROLE_ADMIN = "ROLE_ADMIN";

    @Value("${auth.init.admin.email}")
    private String adminEmail;

    @Value("${auth.init.admin.password}")
    private String adminPassword;

    @Value("${auth.init.admin.nickname}")
    private String adminNickname;

    @Value("${auth.init.admin-client.client-id}")
    private String adminClientId;

    @Value("${auth.init.admin-client.client-secret}")
    private String adminClientSecret;

    @Value("${auth.init.admin-client.redirect-uri}")
    private String adminRedirectUri;

    @Value("${auth.init.admin-client.post-logout-uri}")
    private String adminPostLogoutUri;

    @Value("${auth.init.m2m-client.client-id}")
    private String m2mClientId;

    @Value("${auth.init.m2m-client.client-secret}")
    private String m2mClientSecret;

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RegisteredClientRepository registeredClientRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        initAdminUser();
        initAdminClient();
        initM2mClient();
    }

    private void initAdminUser() {
        if (userRepository.existsByEmail(adminEmail)) {
            log.info("[PROD_INIT] 관리자 계정 이미 존재함. email={}", adminEmail);
            return;
        }

        Role adminRole = roleRepository.findByName(ROLE_ADMIN)
                .orElseThrow(() -> new IllegalStateException("ROLE_ADMIN 역할이 없습니다. Flyway 마이그레이션을 확인하세요."));

        User admin = User.builder()
                .email(adminEmail)
                .password(passwordEncoder.encode(adminPassword))
                .nickname(adminNickname)
                .build();
        admin.addRole(adminRole);
        userRepository.save(admin);

        log.info("[PROD_INIT] 관리자 계정 생성 완료. email={}", adminEmail);
    }

    private void initAdminClient() {
        if (registeredClientRepository.findByClientId(adminClientId) != null) {
            log.info("[PROD_INIT] 어드민 클라이언트 이미 존재함. clientId={}", adminClientId);
            return;
        }

        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(adminClientId)
                .clientName("어드민 서버")
                .clientSecret(passwordEncoder.encode(adminClientSecret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("openid")
                .scope("profile")
                .redirectUri(adminRedirectUri)
                .postLogoutRedirectUri(adminPostLogoutUri)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(false)
                        .requireAuthorizationConsent(false)
                        .setting("loginPageUri", "/login")
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .refreshTokenTimeToLive(Duration.ofHours(8))
                        .build())
                .build();

        registeredClientRepository.save(client);

        log.info("[PROD_INIT] 어드민 클라이언트 등록 완료. clientId={}", adminClientId);
    }

    private void initM2mClient() {
        if (registeredClientRepository.findByClientId(m2mClientId) != null) {
            log.info("[PROD_INIT] M2M 클라이언트 이미 존재함. clientId={}", m2mClientId);
            return;
        }

        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(m2mClientId)
                .clientName("M2M 클라이언트")
                .clientSecret(passwordEncoder.encode(m2mClientSecret))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .scope("client:manage")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .build())
                .build();

        registeredClientRepository.save(client);

        log.info("[PROD_INIT] M2M 클라이언트 등록 완료. clientId={}", m2mClientId);
    }
}
