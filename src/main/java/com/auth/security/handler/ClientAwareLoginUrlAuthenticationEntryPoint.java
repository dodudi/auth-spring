package com.auth.security.handler;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

@RequiredArgsConstructor
public class ClientAwareLoginUrlAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final RegisteredClientRepository registeredClientRepository;

    @Override
    public void commence(HttpServletRequest request, @NonNull HttpServletResponse response, @NonNull AuthenticationException authException) throws IOException {
        String clientId = request.getParameter("client_id");

        if (clientId != null) {
            RegisteredClient client = registeredClientRepository.findByClientId(clientId);
            if (client != null) {
                String loginPageUri = client.getClientSettings().getSetting("loginPageUri");
                if (loginPageUri != null && !loginPageUri.isBlank()) {
                    response.sendRedirect(loginPageUri);
                    return;
                }
            }
        }

        response.sendRedirect("/oauth/error?error=invalid_request&error_description=Login+page+not+configured+for+this+client");
    }
}
