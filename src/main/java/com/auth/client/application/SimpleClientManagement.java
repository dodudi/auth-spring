package com.auth.client.application;

import com.auth.client.repository.ClientRepository;
import com.auth.client.dto.ClientCreateRequest;
import com.auth.client.dto.ClientDetail;
import com.auth.client.dto.ClientSummary;
import com.auth.client.dto.ClientUpdateRequest;
import com.auth.client.dto.SecretRevealResponse;
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
public class SimpleClientManagement implements ClientManagement {

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
        if (clientRepository.existsByClientId(request.clientId())) {
            throw new AuthException(ErrorCode.CLIENT_ID_ALREADY_EXISTS);
        }

        String rawSecret = UUID.randomUUID().toString();

        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(request.clientId())
                .clientSecret(passwordEncoder.encode(rawSecret))
                .clientName(request.clientName())
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);

        request.grantTypes().forEach(gt -> builder.authorizationGrantType(new AuthorizationGrantType(gt)));
        request.scopes().forEach(builder::scope);
        parseUris(request.redirectUrisRaw()).forEach(builder::redirectUri);
        parseUris(request.postLogoutRedirectUrisRaw()).forEach(builder::postLogoutRedirectUri);

        RegisteredClient client = builder
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(request.requirePkce())
                        .requireAuthorizationConsent(true)
                        .setting("loginPageUri", request.loginPageUri())
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(request.accessTokenTtlMinutes()))
                        .refreshTokenTimeToLive(Duration.ofDays(request.refreshTokenTtlDays()))
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

        Set<String> newUris = parseUris(request.redirectUrisRaw());
        Set<String> newPostLogoutUris = parseUris(request.postLogoutRedirectUrisRaw());

        RegisteredClient updated = RegisteredClient.from(existing)
                .clientName(request.clientName())
                .authorizationGrantTypes(types -> {
                    types.clear();
                    request.grantTypes().forEach(gt -> types.add(new AuthorizationGrantType(gt)));
                })
                .scopes(scopes -> {
                    scopes.clear();
                    scopes.addAll(request.scopes());
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
                        .requireProofKey(request.requirePkce())
                        .requireAuthorizationConsent(true)
                        .setting("loginPageUri", request.loginPageUri())
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(request.accessTokenTtlMinutes()))
                        .refreshTokenTimeToLive(Duration.ofDays(request.refreshTokenTtlDays()))
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
