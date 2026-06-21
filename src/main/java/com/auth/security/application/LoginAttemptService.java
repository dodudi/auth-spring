package com.auth.security.application;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;

@Slf4j
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
        try {
            redisTemplate.delete(EMAIL_KEY_PREFIX + email);
            redisTemplate.delete(IP_KEY_PREFIX + ip);
        } catch (Exception e) {
            log.warn("[LOGIN_ATTEMPT] Redis 장애로 실패 횟수 초기화 생략. email={}", email, e);
        }
    }

    public boolean isEmailBlocked(String email) {
        return isBlocked(EMAIL_KEY_PREFIX + email);
    }

    public boolean isIpBlocked(String ip) {
        return isBlocked(IP_KEY_PREFIX + ip);
    }

    private void increment(String key) {
        try {
            redisTemplate.execute(INCREMENT_WITH_TTL, List.of(key), String.valueOf(BLOCK_DURATION.getSeconds()));
        } catch (Exception e) {
            log.warn("[LOGIN_ATTEMPT] Redis 장애로 실패 횟수 기록 생략. key={}", key, e);
        }
    }

    private boolean isBlocked(String key) {
        try {
            String value = redisTemplate.opsForValue().get(key);
            return value != null && Integer.parseInt(value) >= MAX_ATTEMPTS;
        } catch (Exception e) {
            log.warn("[LOGIN_ATTEMPT] Redis 장애로 차단 여부 확인 불가, 통과 처리. key={}", key, e);
            return false;
        }
    }
}
