package com.auth.user.application;

import com.auth.common.exception.AuthException;
import com.auth.common.exception.ErrorCode;
import com.auth.security.application.TokenRevocationService;
import com.auth.user.domain.Role;
import com.auth.user.domain.User;
import com.auth.user.dto.ChangePasswordRequest;
import com.auth.user.dto.SignUpRequest;
import com.auth.user.dto.UpdateNicknameRequest;
import com.auth.user.dto.UserResponse;
import com.auth.user.repository.RoleRepository;
import com.auth.user.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenRevocationService tokenRevocationService;

    public UserResponse signUp(SignUpRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new AuthException(ErrorCode.EMAIL_ALREADY_EXISTS);
        }

        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new AuthException(ErrorCode.INTERNAL_SERVER_ERROR));

        User user = User.builder()
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .nickname(request.nickname())
                .build();
        user.addRole(userRole);

        User saved = userRepository.save(user);
        log.info("[USER_SIGNUP] email={}", saved.getEmail());
        return UserResponse.from(saved);
    }

    @Transactional(readOnly = true)
    public UserResponse getMe(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));
        return UserResponse.from(user);
    }

    public UserResponse updateNickname(UUID userId, UpdateNicknameRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));
        user.updateNickname(request.nickname());
        return UserResponse.from(user);
    }

    public void changePassword(UUID userId, ChangePasswordRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));

        if (!passwordEncoder.matches(request.currentPassword(), user.getPassword())) {
            throw new AuthException(ErrorCode.INVALID_PASSWORD);
        }

        user.changePassword(passwordEncoder.encode(request.newPassword()));
        log.info("[PASSWORD_CHANGE] userId={}", user.getId());
    }

    public void withdraw(UUID userId) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new AuthException(ErrorCode.USER_NOT_FOUND));
        user.withdraw();
        tokenRevocationService.revoke(userId);
        log.info("[USER_WITHDRAW] userId={}", user.getId());
    }
}
