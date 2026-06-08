package com.auth.client.dto;

public record SecretRevealResponse(
        String id,
        String clientId,
        String rawSecret
) {}
