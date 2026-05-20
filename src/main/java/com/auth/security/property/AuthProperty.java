package com.auth.security.property;

import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Getter
@Component
public class AuthProperty {

    private final String issuerUri;

    public AuthProperty(@Value("${auth.issuer-uri}") String issuerUri) {
        this.issuerUri = issuerUri;
    }
}
