package com.auth.admin.dto;

import java.time.Instant;

public record ClientSummary(
        String id,
        String clientId,
        String clientName,
        String authorizationGrantTypes,
        String scopes,
        Instant issuedAt
) {}
