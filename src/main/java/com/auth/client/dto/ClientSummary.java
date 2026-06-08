package com.auth.client.dto;

import java.time.Instant;

public record ClientSummary(
        String id,
        String clientId,
        String clientName,
        String authorizationGrantTypes,
        String scopes,
        Instant issuedAt
) {}
