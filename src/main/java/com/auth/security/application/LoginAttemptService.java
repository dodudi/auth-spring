package com.auth.security.application;

import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
@RequiredArgsConstructor
public class LoginAttemptService {

    private final StringRedisTemplate redisTemplate;

    private static final String EMAIL_KEY_PREFIX = "login:fail:email:";
    private static final String IP_KEY_PREFIX = "login:fail:ip:";
    private static final int MAX_ATTEMPTS = 5;
    private static final Duration BLOCK_DURATION = Duration.ofMinutes(10);

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
        Long count = redisTemplate.opsForValue().increment(key);
        if (count != null && count == 1) {
            redisTemplate.expire(key, BLOCK_DURATION);
        }
    }

    private boolean isBlocked(String key) {
        String value = redisTemplate.opsForValue().get(key);
        return value != null && Integer.parseInt(value) >= MAX_ATTEMPTS;
    }
}
