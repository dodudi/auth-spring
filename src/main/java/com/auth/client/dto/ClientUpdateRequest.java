package com.auth.client.dto;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;

import java.util.Set;

public record ClientUpdateRequest(
        @NotBlank String clientName,
        @NotBlank String loginPageUri,
        Set<String> grantTypes,
        Set<String> scopes,
        String redirectUrisRaw,
        String postLogoutRedirectUrisRaw,
        boolean requirePkce,
        @Min(1) @Max(1440) int accessTokenTtlMinutes,
        @Min(1) @Max(365) int refreshTokenTtlDays
) {
    public ClientUpdateRequest {
        loginPageUri = loginPageUri != null ? loginPageUri : "";
        grantTypes = grantTypes != null ? grantTypes : Set.of();
        scopes = scopes != null ? scopes : Set.of();
        redirectUrisRaw = redirectUrisRaw != null ? redirectUrisRaw : "";
        postLogoutRedirectUrisRaw = postLogoutRedirectUrisRaw != null ? postLogoutRedirectUrisRaw : "";
        accessTokenTtlMinutes = accessTokenTtlMinutes == 0 ? 60 : accessTokenTtlMinutes;
        refreshTokenTtlDays = refreshTokenTtlDays == 0 ? 30 : refreshTokenTtlDays;
    }
}
