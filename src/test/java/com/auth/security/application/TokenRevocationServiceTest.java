package com.auth.security.application;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
class TokenRevocationServiceTest {

    @Mock
    private StringRedisTemplate redisTemplate;
    @InjectMocks
    private TokenRevocationService tokenRevocationService;

    @Test
    @SuppressWarnings("unchecked")
    void revoke_현재_시각을_Redis에_기록() {
        // given
        UUID userId = UUID.randomUUID();
        ValueOperations<String, String> valueOps = mock(ValueOperations.class);
        given(redisTemplate.opsForValue()).willReturn(valueOps);

        // when & then
        assertThatCode(() -> tokenRevocationService.revoke(userId)).doesNotThrowAnyException();
    }

    @Test
    @SuppressWarnings("unchecked")
    void revoke_Redis_장애시_예외_미전파() {
        // given
        UUID userId = UUID.randomUUID();
        given(redisTemplate.opsForValue()).willThrow(new RuntimeException("Redis down"));

        // when & then
        assertThatCode(() -> tokenRevocationService.revoke(userId)).doesNotThrowAnyException();
    }

    @Test
    @SuppressWarnings("unchecked")
    void isRevoked_무효화_기록이_없으면_false_반환() {
        // given
        UUID userId = UUID.randomUUID();
        ValueOperations<String, String> valueOps = mock(ValueOperations.class);
        given(redisTemplate.opsForValue()).willReturn(valueOps);
        given(valueOps.get("auth:revoked-at:" + userId)).willReturn(null);

        // when & then
        assertThat(tokenRevocationService.isRevoked(userId, Instant.now())).isFalse();
    }

    @Test
    @SuppressWarnings("unchecked")
    void isRevoked_토큰발급시각이_무효화시각보다_이전이면_true_반환() {
        // given
        UUID userId = UUID.randomUUID();
        Instant revokedAt = Instant.now();
        Instant issuedAt = revokedAt.minus(1, ChronoUnit.HOURS);
        ValueOperations<String, String> valueOps = mock(ValueOperations.class);
        given(redisTemplate.opsForValue()).willReturn(valueOps);
        given(valueOps.get("auth:revoked-at:" + userId)).willReturn(String.valueOf(revokedAt.getEpochSecond()));

        // when & then
        assertThat(tokenRevocationService.isRevoked(userId, issuedAt)).isTrue();
    }

    @Test
    @SuppressWarnings("unchecked")
    void isRevoked_토큰발급시각이_무효화시각보다_이후면_false_반환() {
        // given
        UUID userId = UUID.randomUUID();
        Instant revokedAt = Instant.now().minus(1, ChronoUnit.HOURS);
        Instant issuedAt = Instant.now();
        ValueOperations<String, String> valueOps = mock(ValueOperations.class);
        given(redisTemplate.opsForValue()).willReturn(valueOps);
        given(valueOps.get("auth:revoked-at:" + userId)).willReturn(String.valueOf(revokedAt.getEpochSecond()));

        // when & then
        assertThat(tokenRevocationService.isRevoked(userId, issuedAt)).isFalse();
    }

    @Test
    @SuppressWarnings("unchecked")
    void isRevoked_Redis_장애시_false_반환() {
        // given
        UUID userId = UUID.randomUUID();
        given(redisTemplate.opsForValue()).willThrow(new RuntimeException("Redis down"));

        // when & then
        assertThat(tokenRevocationService.isRevoked(userId, Instant.now())).isFalse();
    }
}
