package com.auth.user.application;

import com.auth.common.exception.AuthException;
import com.auth.common.exception.ErrorCode;
import com.auth.user.domain.Role;
import com.auth.user.domain.RoleRepository;
import com.auth.user.domain.User;
import com.auth.user.domain.UserRepository;
import com.auth.user.dto.SignUpRequest;
import com.auth.user.dto.UpdateNicknameRequest;
import com.auth.user.dto.UserResponse;
import com.auth.user.dto.VerifyEmailRequest;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class UserService {

    private static final String EMAIL_VERIFY_KEY_PREFIX = "email:verify:";
    private static final Duration EMAIL_VERIFY_TTL = Duration.ofHours(24);

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final StringRedisTemplate redisTemplate;

    public UserResponse signUp(SignUpRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new AuthException(ErrorCode.EMAIL_ALREADY_EXISTS);
        }

        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new IllegalStateException("ROLE_USER not found in database"));

        User user = User.builder()
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .nickname(request.nickname())
                .build();
        user.addRole(userRole);

        User saved = userRepository.save(user);

//        String token = UUID.randomUUID().toString();
//        redisTemplate.opsForValue().set(EMAIL_VERIFY_KEY_PREFIX + token, saved.getId().toString(), EMAIL_VERIFY_TTL);

        // TODO: 실제 이메일 발송으로 교체 (현재는 로그로 대체)
//        log.info("[EMAIL VERIFICATION] email={}, token={}", saved.getEmail(), token);

        return UserResponse.from(saved);
    }

    @Transactional(readOnly = true)
    public UserResponse getMe(String email) {
        User user = userRepository.findByEmailWithRoles(email)
                .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));
        return UserResponse.from(user);
    }

    public UserResponse updateNickname(String email, UpdateNicknameRequest request) {
        User user = userRepository.findByEmailWithRoles(email)
                .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));
        user.updateNickname(request.nickname());
        return UserResponse.from(user);
    }

    public void withdraw(String email) {
        User user = userRepository.findByEmailWithRoles(email)
                .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));
        user.withdraw();
    }

    public void verifyEmail(VerifyEmailRequest request) {
        String key = EMAIL_VERIFY_KEY_PREFIX + request.token();
        String userId = redisTemplate.opsForValue().get(key);

        if (userId == null) {
            throw new AuthException(ErrorCode.INVALID_TOKEN);
        }

        User user = userRepository.findById(UUID.fromString(userId))
                .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));

        user.verifyEmail();
        redisTemplate.delete(key);
    }
}
