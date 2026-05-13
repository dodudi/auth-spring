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
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

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
}
