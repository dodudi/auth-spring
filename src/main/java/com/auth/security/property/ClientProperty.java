package com.auth.security.property;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Getter
@Component
public class ClientProperty {

    private final String loginRedirectUri;

    public ClientProperty(
            @Value("${auth.client.login-redirect-uri}") String loginRedirectUri
    ) {
        this.loginRedirectUri = loginRedirectUri;
    }
}
