package com.auth.common.init;

import com.auth.client.domain.ClientRepository;
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
public class LocalAdminClientInitializer implements ApplicationRunner {

    private static final String ADMIN_CLIENT_ID = "local-admin-server";
    private static final String ADMIN_CLIENT_SECRET = "admin-secret-local";
    private static final String ADMIN_CLIENT_NAME = "로컬 어드민 서버";
    private static final String ADMIN_REDIRECT_URI = "http://localhost:8090/login/oauth2/code/auth-server";
    private static final String ADMIN_POST_LOGOUT_URI = "http://localhost:8090";

    private final RegisteredClientRepository registeredClientRepository;
    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        initAdminClient();
    }

    private void initAdminClient() {
        RegisteredClient existing = registeredClientRepository.findByClientId(ADMIN_CLIENT_ID);
        if (existing != null) {
            clientRepository.deleteById(existing.getId());
            log.debug("[LOCAL_INIT] 기존 어드민 클라이언트 삭제 후 재등록. clientId={}", ADMIN_CLIENT_ID);
        }

        RegisteredClient adminClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(ADMIN_CLIENT_ID)
                .clientSecret(passwordEncoder.encode(ADMIN_CLIENT_SECRET))
                .clientName(ADMIN_CLIENT_NAME)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .scope("openid")
                .scope("profile")
                .redirectUri(ADMIN_REDIRECT_URI)
                .postLogoutRedirectUri(ADMIN_POST_LOGOUT_URI)
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

        registeredClientRepository.save(adminClient);

        log.info("[LOCAL_INIT] 어드민 클라이언트 등록 완료. clientId={}, secret=admin-secret-local", ADMIN_CLIENT_ID);
    }
}
