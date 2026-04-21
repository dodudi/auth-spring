package com.auth.user.dto;

import com.auth.user.domain.User;

import java.time.Instant;
import java.time.LocalDateTime;
import java.util.UUID;

public record UserResponse(
        UUID id,
        String email,
        String nickname,
        String status,
        boolean emailVerified,
        Instant createdAt
) {
    public static UserResponse from(User user) {
        return new UserResponse(
                user.getId(),
                user.getEmail(),
                user.getNickname(),
                user.getStatus().name(),
                user.isEmailVerified(),
                user.getCreatedAt()
        );
    }
}
