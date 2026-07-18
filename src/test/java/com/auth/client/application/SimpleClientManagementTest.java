package com.auth.client.application;

import com.auth.client.dto.ClientCreateRequest;
import com.auth.client.dto.ClientDetail;
import com.auth.client.dto.ClientSummary;
import com.auth.client.dto.ClientUpdateRequest;
import com.auth.client.dto.SecretRevealResponse;
import com.auth.client.repository.ClientRepository;
import com.auth.common.exception.AuthException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class SimpleClientManagementTest {

    @Mock
    private RegisteredClientRepository registeredClientRepository;
    @Mock
    private ClientRepository clientRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @InjectMocks
    private SimpleClientManagement clientManagement;

    private RegisteredClient createClientFixture(String id, String clientId) {
        return RegisteredClient.withId(id)
                .clientId(clientId)
                .clientSecret("encoded-secret")
                .clientName("Test Client")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("https://example.com/callback")
                .scope("openid")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientSettings(ClientSettings.builder()
                        .setting("loginPageUri", "https://example.com/login")
                        .build())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(30))
                        .refreshTokenTimeToLive(Duration.ofDays(7))
                        .build())
                .build();
    }

    @Test
    void findAll_클라이언트_목록_반환() {
        // given
        List<ClientSummary> summaries = List.of(
                new ClientSummary("id1", "client-1", "Client One", "authorization_code", "openid", Instant.now())
        );
        given(clientRepository.findAll()).willReturn(summaries);

        // when
        List<ClientSummary> result = clientManagement.findAll();

        // then
        assertThat(result).hasSize(1);
        assertThat(result.get(0).clientId()).isEqualTo("client-1");
    }

    @Test
    void getDetail_존재하는_id_조회시_ClientDetail_반환() {
        // given
        String id = UUID.randomUUID().toString();
        RegisteredClient client = createClientFixture(id, "test-client");
        given(registeredClientRepository.findById(id)).willReturn(client);

        // when
        ClientDetail detail = clientManagement.getDetail(id);

        // then
        assertThat(detail.clientId()).isEqualTo("test-client");
        assertThat(detail.clientName()).isEqualTo("Test Client");
        assertThat(detail.accessTokenTtlMinutes()).isEqualTo(30);
        assertThat(detail.refreshTokenTtlDays()).isEqualTo(7);
        assertThat(detail.loginPageUri()).isEqualTo("https://example.com/login");
    }

    @Test
    void getDetail_존재하지_않는_id_조회시_CLIENT_NOT_FOUND_예외_발생() {
        // given
        given(registeredClientRepository.findById(anyString())).willReturn(null);

        // when & then
        assertThatThrownBy(() -> clientManagement.getDetail("non-existent-id"))
                .isInstanceOf(AuthException.class);
    }

    @Test
    void create_중복_clientId_입력시_CLIENT_ID_ALREADY_EXISTS_예외_발생() {
        // given
        ClientCreateRequest request = new ClientCreateRequest(
                "existing-client", null, null, null, null, null, null, false, 0, 0);
        given(clientRepository.existsByClientId("existing-client")).willReturn(true);

        // when & then
        assertThatThrownBy(() -> clientManagement.create(request))
                .isInstanceOf(AuthException.class);
    }

    @Test
    void create_유효한_요청_입력시_SecretRevealResponse_반환() {
        // given
        ClientCreateRequest request = new ClientCreateRequest(
                "new-client", "New Client", "https://example.com/login",
                Set.of("authorization_code"), Set.of("openid"),
                "https://example.com/callback", null, false, 30, 7);

        given(clientRepository.existsByClientId("new-client")).willReturn(false);
        given(passwordEncoder.encode(anyString())).willReturn("encoded-secret");

        // when
        SecretRevealResponse response = clientManagement.create(request);

        // then
        assertThat(response.clientId()).isEqualTo("new-client");
        assertThat(response.rawSecret()).isNotBlank();
        verify(registeredClientRepository).save(any(RegisteredClient.class));
        verify(passwordEncoder).encode(response.rawSecret());
    }

    @Test
    void update_존재하지_않는_id_입력시_CLIENT_NOT_FOUND_예외_발생() {
        // given
        given(registeredClientRepository.findById(anyString())).willReturn(null);
        ClientUpdateRequest request = new ClientUpdateRequest(
                null, null, null, null, null, null, false, 0, 0);

        // when & then
        assertThatThrownBy(() -> clientManagement.update("non-existent-id", request))
                .isInstanceOf(AuthException.class);
    }

    @Test
    void update_유효한_요청_입력시_변경된_클라이언트_저장() {
        // given
        String id = UUID.randomUUID().toString();
        RegisteredClient existing = createClientFixture(id, "test-client");

        ClientUpdateRequest request = new ClientUpdateRequest(
                "Updated Client", "https://updated.com/login",
                Set.of("authorization_code"), Set.of("openid", "profile"),
                "https://updated.com/callback", null, false, 60, 14);

        given(registeredClientRepository.findById(id)).willReturn(existing);

        // when
        clientManagement.update(id, request);

        // then
        ArgumentCaptor<RegisteredClient> captor = ArgumentCaptor.forClass(RegisteredClient.class);
        verify(registeredClientRepository).save(captor.capture());
        assertThat(captor.getValue().getClientName()).isEqualTo("Updated Client");
        assertThat(captor.getValue().getScopes()).contains("openid", "profile");
    }

    @Test
    void delete_존재하지_않는_id_입력시_CLIENT_NOT_FOUND_예외_발생() {
        // given
        given(registeredClientRepository.findById(anyString())).willReturn(null);

        // when & then
        assertThatThrownBy(() -> clientManagement.delete("non-existent-id"))
                .isInstanceOf(AuthException.class);
    }

    @Test
    void delete_존재하는_id_입력시_deleteById_호출() {
        // given
        String id = UUID.randomUUID().toString();
        RegisteredClient client = createClientFixture(id, "test-client");
        given(registeredClientRepository.findById(id)).willReturn(client);

        // when
        clientManagement.delete(id);

        // then
        verify(clientRepository).deleteById(id);
    }

    @Test
    void regenerateSecret_존재하지_않는_id_입력시_CLIENT_NOT_FOUND_예외_발생() {
        // given
        given(registeredClientRepository.findById(anyString())).willReturn(null);

        // when & then
        assertThatThrownBy(() -> clientManagement.regenerateSecret("non-existent-id"))
                .isInstanceOf(AuthException.class);
    }

    @Test
    void regenerateSecret_존재하는_id_입력시_새_시크릿_반환() {
        // given
        String id = UUID.randomUUID().toString();
        RegisteredClient existing = createClientFixture(id, "test-client");
        given(registeredClientRepository.findById(id)).willReturn(existing);
        given(passwordEncoder.encode(anyString())).willReturn("new-encoded-secret");

        // when
        SecretRevealResponse response = clientManagement.regenerateSecret(id);

        // then
        assertThat(response.clientId()).isEqualTo("test-client");
        assertThat(response.rawSecret()).isNotBlank();
        verify(registeredClientRepository).save(any(RegisteredClient.class));
        verify(passwordEncoder).encode(response.rawSecret());
    }
}
