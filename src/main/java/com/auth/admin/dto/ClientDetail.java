package com.auth.admin.dto;

import java.util.Set;

public record ClientDetail(
        String id,
        String clientId,
        String clientName,
        Set<String> grantTypes,
        Set<String> scopes,
        String redirectUrisRaw,
        String postLogoutRedirectUrisRaw,
        boolean requirePkce,
        int accessTokenTtlMinutes,
        int refreshTokenTtlDays
) {}
