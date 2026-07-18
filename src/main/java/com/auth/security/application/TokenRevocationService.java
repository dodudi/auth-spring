package com.auth.security.application;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class TokenRevocationService {

    private final StringRedisTemplate redisTemplate;

    private static final String REVOKED_AT_KEY_PREFIX = "auth:revoked-at:";

    public void revoke(UUID userId) {
        try {
            redisTemplate.opsForValue().set(REVOKED_AT_KEY_PREFIX + userId, String.valueOf(Instant.now().getEpochSecond()));
        } catch (Exception e) {
            log.warn("[TOKEN_REVOKE] Redis 장애로 토큰 무효화 기록 실패. userId={}", userId, e);
        }
    }

    public boolean isRevoked(UUID userId, Instant issuedAt) {
        try {
            String value = redisTemplate.opsForValue().get(REVOKED_AT_KEY_PREFIX + userId);
            if (value == null) {
                return false;
            }
            Instant revokedAt = Instant.ofEpochSecond(Long.parseLong(value));
            return !issuedAt.isAfter(revokedAt);
        } catch (Exception e) {
            log.warn("[TOKEN_REVOKE] Redis 장애로 토큰 무효화 여부 확인 불가, 통과 처리. userId={}", userId, e);
            return false;
        }
    }
}
