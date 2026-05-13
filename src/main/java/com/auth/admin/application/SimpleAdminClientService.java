package com.auth.admin.application;

import com.auth.admin.domain.ClientRepository;
import com.auth.admin.dto.ClientCreateRequest;
import com.auth.admin.dto.ClientDetail;
import com.auth.admin.dto.ClientSummary;
import com.auth.admin.dto.ClientUpdateRequest;
import com.auth.admin.dto.SecretRevealResponse;
import com.auth.common.exception.AuthException;
import com.auth.common.exception.ErrorCode;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
public class SimpleAdminClientService implements AdminClientManagement {

    private final RegisteredClientRepository registeredClientRepository;
    private final ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public List<ClientSummary> findAll() {
        return clientRepository.findAll();
    }

    @Override
    public ClientDetail getDetail(String id) {
        RegisteredClient client = registeredClientRepository.findById(id);
        if (client == null) {
            throw new AuthException(ErrorCode.CLIENT_NOT_FOUND);
        }
        return toDetail(client);
    }

    @Override
    public SecretRevealResponse create(ClientCreateRequest request) {
        if (clientRepository.existsByClientId(request.getClientId())) {
            throw new AuthException(ErrorCode.CLIENT_ID_ALREADY_EXISTS);
        }

        String rawSecret = UUID.randomUUID().toString();

        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(request.getClientId())
                .clientSecret(passwordEncoder.encode(rawSecret))
                .clientName(request.getClientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

        request.getGrantTypes().forEach(gt -> builder.authorizationGrantType(new AuthorizationGrantType(gt)));
        request.getScopes().forEach(builder::scope);
        parseUris(request.getRedirectUrisRaw()).forEach(builder::redirectUri);
        parseUris(request.getPostLogoutRedirectUrisRaw()).forEach(builder::postLogoutRedirectUri);

        RegisteredClient client = builder
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(request.isRequirePkce())
                        .requireAuthorizationConsent(true)
                        .setting("loginPageUri", request.getLoginPageUri())
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(request.getAccessTokenTtlMinutes()))
                        .refreshTokenTimeToLive(Duration.ofDays(request.getRefreshTokenTtlDays()))
                        .build())
                .build();

        registeredClientRepository.save(client);
        log.info("[CLIENT_CREATE] clientId={}", client.getClientId());
        return new SecretRevealResponse(client.getId(), client.getClientId(), rawSecret);
    }

    @Override
    public void update(String id, ClientUpdateRequest request) {
        RegisteredClient existing = registeredClientRepository.findById(id);
        if (existing == null) {
            throw new AuthException(ErrorCode.CLIENT_NOT_FOUND);
        }

        Set<String> newUris = parseUris(request.getRedirectUrisRaw());
        Set<String> newPostLogoutUris = parseUris(request.getPostLogoutRedirectUrisRaw());

        RegisteredClient updated = RegisteredClient.from(existing)
                .clientName(request.getClientName())
                .authorizationGrantTypes(types -> {
                    types.clear();
                    request.getGrantTypes().forEach(gt -> types.add(new AuthorizationGrantType(gt)));
                })
                .scopes(scopes -> {
                    scopes.clear();
                    scopes.addAll(request.getScopes());
                })
                .redirectUris(uris -> {
                    uris.clear();
                    uris.addAll(newUris);
                })
                .postLogoutRedirectUris(uris -> {
                    uris.clear();
                    uris.addAll(newPostLogoutUris);
                })
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(request.isRequirePkce())
                        .requireAuthorizationConsent(true)
                        .setting("loginPageUri", request.getLoginPageUri())
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(request.getAccessTokenTtlMinutes()))
                        .refreshTokenTimeToLive(Duration.ofDays(request.getRefreshTokenTtlDays()))
                        .build())
                .build();

        registeredClientRepository.save(updated);
        log.info("[CLIENT_UPDATE] clientId={}", existing.getClientId());
    }

    @Override
    public void delete(String id) {
        RegisteredClient existing = registeredClientRepository.findById(id);
        if (existing == null) {
            throw new AuthException(ErrorCode.CLIENT_NOT_FOUND);
        }
        clientRepository.deleteById(id);
        log.info("[CLIENT_DELETE] clientId={}", existing.getClientId());
    }

    @Override
    public SecretRevealResponse regenerateSecret(String id) {
        RegisteredClient existing = registeredClientRepository.findById(id);
        if (existing == null) {
            throw new AuthException(ErrorCode.CLIENT_NOT_FOUND);
        }

        String rawSecret = UUID.randomUUID().toString();
        RegisteredClient updated = RegisteredClient.from(existing)
                .clientSecret(passwordEncoder.encode(rawSecret))
                .build();

        registeredClientRepository.save(updated);
        log.info("[CLIENT_SECRET_ROTATE] clientId={}", existing.getClientId());
        return new SecretRevealResponse(id, existing.getClientId(), rawSecret);
    }

    private ClientDetail toDetail(RegisteredClient client) {
        Set<String> grantTypes = client.getAuthorizationGrantTypes().stream()
                .map(AuthorizationGrantType::getValue)
                .collect(Collectors.toSet());

        String loginPageUri = client.getClientSettings().getSetting("loginPageUri");
        return new ClientDetail(
                client.getId(),
                client.getClientId(),
                client.getClientName(),
                grantTypes,
                client.getScopes(),
                String.join("\n", client.getRedirectUris()),
                String.join("\n", client.getPostLogoutRedirectUris()),
                client.getClientSettings().isRequireProofKey(),
                (int) client.getTokenSettings().getAccessTokenTimeToLive().toMinutes(),
                (int) client.getTokenSettings().getRefreshTokenTimeToLive().toDays(),
                loginPageUri != null ? loginPageUri : ""
        );
    }

    private Set<String> parseUris(String raw) {
        if (raw == null || raw.isBlank()) return Set.of();
        return Arrays.stream(raw.split("\\r?\\n"))
                .map(String::trim)
                .filter(s -> !s.isBlank())
                .collect(Collectors.toSet());
    }
}
