package com.auth.admin.dto;

public record SecretRevealResponse(
        String id,
        String clientId,
        String rawSecret
) {}
