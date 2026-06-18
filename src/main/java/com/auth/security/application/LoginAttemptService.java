package com.auth.security.application;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;

@Service
@RequiredArgsConstructor
public class LoginAttemptService {

    private final StringRedisTemplate redisTemplate;

    private static final String EMAIL_KEY_PREFIX = "login:fail:email:";
    private static final String IP_KEY_PREFIX = "login:fail:ip:";
    private static final int MAX_ATTEMPTS = 5;
    private static final Duration BLOCK_DURATION = Duration.ofMinutes(10);

    // INCR와 EXPIRE를 원자적으로 실행 — 첫 증가 시에만 TTL 설정
    private static final RedisScript<Long> INCREMENT_WITH_TTL = RedisScript.of(
            "local count = redis.call('INCR', KEYS[1]) " +
            "if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end " +
            "return count",
            Long.class
    );

    public void recordFailure(String email, String ip) {
        increment(EMAIL_KEY_PREFIX + email);
        increment(IP_KEY_PREFIX + ip);
    }

    public void clearFailures(String email, String ip) {
        redisTemplate.delete(EMAIL_KEY_PREFIX + email);
        redisTemplate.delete(IP_KEY_PREFIX + ip);
    }

    public boolean isEmailBlocked(String email) {
        return isBlocked(EMAIL_KEY_PREFIX + email);
    }

    public boolean isIpBlocked(String ip) {
        return isBlocked(IP_KEY_PREFIX + ip);
    }

    private void increment(String key) {
        redisTemplate.execute(INCREMENT_WITH_TTL, List.of(key), String.valueOf(BLOCK_DURATION.getSeconds()));
    }

    private boolean isBlocked(String key) {
        String value = redisTemplate.opsForValue().get(key);
        return value != null && Integer.parseInt(value) >= MAX_ATTEMPTS;
    }
}
