package com.auth.security.application;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.data.redis.core.script.RedisScript;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class LoginAttemptServiceTest {

    @Mock
    private StringRedisTemplate redisTemplate;
    @InjectMocks
    private LoginAttemptService loginAttemptService;

    @Test
    @SuppressWarnings("unchecked")
    void recordFailure_이메일과_IP에_실패_횟수_증가() {
        // when
        loginAttemptService.recordFailure("test@example.com", "127.0.0.1");

        // then: email 키 + ip 키 = 2회 execute 호출
        verify(redisTemplate, times(2)).execute(any(RedisScript.class), anyList(), any());
    }

    @Test
    @SuppressWarnings("unchecked")
    void recordFailure_Redis_장애시_예외_미전파() {
        // given
        given(redisTemplate.execute(any(RedisScript.class), anyList(), any()))
                .willThrow(new RuntimeException("Redis down"));

        // when & then
        assertThatCode(() -> loginAttemptService.recordFailure("test@example.com", "127.0.0.1"))
                .doesNotThrowAnyException();
    }

    @Test
    void clearFailures_이메일과_IP_키_삭제() {
        // when
        loginAttemptService.clearFailures("test@example.com", "127.0.0.1");

        // then
        verify(redisTemplate, times(2)).delete(anyString());
    }

    @Test
    void clearFailures_Redis_장애시_예외_미전파() {
        // given
        given(redisTemplate.delete(anyString())).willThrow(new RuntimeException("Redis down"));

        // when & then
        assertThatCode(() -> loginAttemptService.clearFailures("test@example.com", "127.0.0.1"))
                .doesNotThrowAnyException();
    }

    @Test
    @SuppressWarnings("unchecked")
    void isEmailBlocked_5회_미만이면_false_반환() {
        // given
        ValueOperations<String, String> valueOps = mock(ValueOperations.class);
        given(redisTemplate.opsForValue()).willReturn(valueOps);
        given(valueOps.get("login:fail:email:test@example.com")).willReturn("4");

        // when & then
        assertThat(loginAttemptService.isEmailBlocked("test@example.com")).isFalse();
    }

    @Test
    @SuppressWarnings("unchecked")
    void isEmailBlocked_5회_이상이면_true_반환() {
        // given
        ValueOperations<String, String> valueOps = mock(ValueOperations.class);
        given(redisTemplate.opsForValue()).willReturn(valueOps);
        given(valueOps.get("login:fail:email:test@example.com")).willReturn("5");

        // when & then
        assertThat(loginAttemptService.isEmailBlocked("test@example.com")).isTrue();
    }

    @Test
    void isEmailBlocked_Redis_장애시_false_반환() {
        // given
        given(redisTemplate.opsForValue()).willThrow(new RuntimeException("Redis down"));

        // when & then
        assertThat(loginAttemptService.isEmailBlocked("test@example.com")).isFalse();
    }

    @Test
    @SuppressWarnings("unchecked")
    void isIpBlocked_5회_미만이면_false_반환() {
        // given
        ValueOperations<String, String> valueOps = mock(ValueOperations.class);
        given(redisTemplate.opsForValue()).willReturn(valueOps);
        given(valueOps.get("login:fail:ip:127.0.0.1")).willReturn("3");

        // when & then
        assertThat(loginAttemptService.isIpBlocked("127.0.0.1")).isFalse();
    }

    @Test
    @SuppressWarnings("unchecked")
    void isIpBlocked_5회_이상이면_true_반환() {
        // given
        ValueOperations<String, String> valueOps = mock(ValueOperations.class);
        given(redisTemplate.opsForValue()).willReturn(valueOps);
        given(valueOps.get("login:fail:ip:127.0.0.1")).willReturn("5");

        // when & then
        assertThat(loginAttemptService.isIpBlocked("127.0.0.1")).isTrue();
    }

    @Test
    void isIpBlocked_Redis_장애시_false_반환() {
        // given
        given(redisTemplate.opsForValue()).willThrow(new RuntimeException("Redis down"));

        // when & then
        assertThat(loginAttemptService.isIpBlocked("127.0.0.1")).isFalse();
    }
}
