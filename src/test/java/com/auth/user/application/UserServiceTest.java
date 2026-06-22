package com.auth.user.application;

import com.auth.common.exception.AuthException;
import com.auth.user.domain.Role;
import com.auth.user.domain.RoleRepository;
import com.auth.user.domain.User;
import com.auth.user.domain.UserRepository;
import com.auth.user.domain.UserStatus;
import com.auth.user.dto.SignUpRequest;
import com.auth.user.dto.UpdateNicknameRequest;
import com.auth.user.dto.UserResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class UserServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private RoleRepository roleRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @InjectMocks
    private UserService userService;

    @Test
    void signUp_중복_이메일_입력시_EMAIL_ALREADY_EXISTS_예외_발생() {
        // given
        given(userRepository.existsByEmail("test@example.com")).willReturn(true);

        // when & then
        assertThatThrownBy(() -> userService.signUp(new SignUpRequest("test@example.com", "password123", "nickname")))
                .isInstanceOf(AuthException.class);
    }

    @Test
    void signUp_유효한_요청_입력시_UserResponse_반환() {
        // given
        SignUpRequest request = new SignUpRequest("test@example.com", "password123", "nickname");
        Role userRole = mock(Role.class);
        User savedUser = User.builder().email("test@example.com").password("encoded").nickname("nickname").build();
        ReflectionTestUtils.setField(savedUser, "id", UUID.randomUUID());

        given(userRepository.existsByEmail(request.email())).willReturn(false);
        given(roleRepository.findByName("ROLE_USER")).willReturn(Optional.of(userRole));
        given(passwordEncoder.encode(request.password())).willReturn("encoded");
        given(userRepository.save(any(User.class))).willReturn(savedUser);

        // when
        UserResponse response = userService.signUp(request);

        // then
        assertThat(response.email()).isEqualTo("test@example.com");
        assertThat(response.nickname()).isEqualTo("nickname");
        verify(userRepository).save(any(User.class));
    }

    @Test
    void getMe_존재하는_userId_조회시_UserResponse_반환() {
        // given
        UUID userId = UUID.randomUUID();
        User user = User.builder().email("test@example.com").password("encoded").nickname("nickname").build();
        ReflectionTestUtils.setField(user, "id", userId);
        given(userRepository.findById(userId)).willReturn(Optional.of(user));

        // when
        UserResponse response = userService.getMe(userId);

        // then
        assertThat(response.id()).isEqualTo(userId);
        assertThat(response.email()).isEqualTo("test@example.com");
    }

    @Test
    void getMe_존재하지_않는_userId_조회시_USER_NOT_FOUND_예외_발생() {
        // given
        UUID userId = UUID.randomUUID();
        given(userRepository.findById(userId)).willReturn(Optional.empty());

        // when & then
        assertThatThrownBy(() -> userService.getMe(userId))
                .isInstanceOf(AuthException.class);
    }

    @Test
    void updateNickname_존재하는_userId_입력시_닉네임_업데이트된_UserResponse_반환() {
        // given
        UUID userId = UUID.randomUUID();
        User user = User.builder().email("test@example.com").password("encoded").nickname("old").build();
        ReflectionTestUtils.setField(user, "id", userId);
        given(userRepository.findById(userId)).willReturn(Optional.of(user));

        // when
        UserResponse response = userService.updateNickname(userId, new UpdateNicknameRequest("new-nickname"));

        // then
        assertThat(response.nickname()).isEqualTo("new-nickname");
    }

    @Test
    void updateNickname_존재하지_않는_userId_입력시_USER_NOT_FOUND_예외_발생() {
        // given
        UUID userId = UUID.randomUUID();
        given(userRepository.findById(userId)).willReturn(Optional.empty());

        // when & then
        assertThatThrownBy(() -> userService.updateNickname(userId, new UpdateNicknameRequest("new-nickname")))
                .isInstanceOf(AuthException.class);
    }

    @Test
    void withdraw_존재하는_userId_입력시_WITHDRAWN_상태로_변경() {
        // given
        UUID userId = UUID.randomUUID();
        User user = User.builder().email("test@example.com").password("encoded").nickname("nickname").build();
        given(userRepository.findById(userId)).willReturn(Optional.of(user));

        // when
        userService.withdraw(userId);

        // then
        assertThat(user.getStatus()).isEqualTo(UserStatus.WITHDRAWN);
    }

    @Test
    void withdraw_존재하지_않는_userId_입력시_USER_NOT_FOUND_예외_발생() {
        // given
        UUID userId = UUID.randomUUID();
        given(userRepository.findById(userId)).willReturn(Optional.empty());

        // when & then
        assertThatThrownBy(() -> userService.withdraw(userId))
                .isInstanceOf(AuthException.class);
    }
}
