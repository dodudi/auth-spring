package com.auth.common.init;

import com.auth.client.domain.ClientRepository;
import com.auth.user.domain.Role;
import com.auth.user.domain.RoleRepository;
import com.auth.user.domain.User;
import com.auth.user.domain.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
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
@Profile("local")
@RequiredArgsConstructor
public class LocalDataInitializer implements ApplicationRunner {

    private static final String ADMIN_EMAIL = "admin@local.dev";
    private static final String ADMIN_PASSWORD = "admin1234!";
    private static final String ADMIN_NICKNAME = "로컬관리자";
    private static final String ROLE_ADMIN = "ROLE_ADMIN";

    private static final String TEST_CLIENT_ID = "local-test-client";
    private static final String TEST_CLIENT_NAME = "로컬 테스트 클라이언트";
    private static final String TEST_REDIRECT_URI = "http://localhost:3000/callback";
    private static final String TEST_POST_LOGOUT_URI = "http://localhost:3000";

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final RegisteredClientRepository registeredClientRepository;
    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        initAdminUser();
        initTestClient();
    }

    private void initAdminUser() {
        if (userRepository.existsByEmail(ADMIN_EMAIL)) {
            log.debug("[LOCAL_INIT] 관리자 계정 이미 존재함. email={}", ADMIN_EMAIL);
            return;
        }

        Role adminRole = roleRepository.findByName(ROLE_ADMIN)
                .orElseThrow(() -> new IllegalStateException("ROLE_ADMIN 역할이 없습니다. Flyway 마이그레이션을 확인하세요."));

        User admin = User.builder()
                .email(ADMIN_EMAIL)
                .password(passwordEncoder.encode(ADMIN_PASSWORD))
                .nickname(ADMIN_NICKNAME)
                .build();
        admin.addRole(adminRole);
        userRepository.save(admin);

        log.info("[LOCAL_INIT] 관리자 계정 생성 완료. email={}, password={}", ADMIN_EMAIL, ADMIN_PASSWORD);
    }

    private void initTestClient() {
        RegisteredClient existing = registeredClientRepository.findByClientId(TEST_CLIENT_ID);
        if (existing != null) {
            clientRepository.deleteById(existing.getId());
            log.debug("[LOCAL_INIT] 기존 테스트 클라이언트 삭제 후 재등록. clientId={}", TEST_CLIENT_ID);
        }

        RegisteredClient client = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(TEST_CLIENT_ID)
                .clientName(TEST_CLIENT_NAME)
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("openid")
                .scope("profile")
                .redirectUri(TEST_REDIRECT_URI)
                .postLogoutRedirectUri(TEST_POST_LOGOUT_URI)
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(true)
                        .setting("loginPageUri", "/login")
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(60))
                        .refreshTokenTimeToLive(Duration.ofDays(30))
                        .build())
                .build();

        registeredClientRepository.save(client);

        log.info("[LOCAL_INIT] 테스트 클라이언트 등록 완료 (Public Client). clientId={}", TEST_CLIENT_ID);
    }
}
