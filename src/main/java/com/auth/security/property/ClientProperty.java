package com.auth.security.property;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Getter
@Component
public class ClientProperty {

    private final String id;
    private final String secret;
    private final String redirectUri;
    private final String postLogoutRedirectUri;
    private final String loginRedirectUri;

    public ClientProperty(
            @Value("${auth.client.id}") String id,
            @Value("${auth.client.secret}") String secret,
            @Value("${auth.client.redirect-uri}") String redirectUri,
            @Value("${auth.client.post-logout-redirect-uri}") String postLogoutRedirectUri,
            @Value("${auth.client.login-redirect-uri}") String loginRedirectUri
    ) {
        this.id = id;
        this.secret = secret;
        this.redirectUri = redirectUri;
        this.postLogoutRedirectUri = postLogoutRedirectUri;
        this.loginRedirectUri = loginRedirectUri;
    }
}
