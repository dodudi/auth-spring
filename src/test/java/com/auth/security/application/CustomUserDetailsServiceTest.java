package com.auth.security.application;

import com.auth.user.domain.Role;
import com.auth.user.domain.User;
import com.auth.user.domain.UserRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
class CustomUserDetailsServiceTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private LoginAttemptService loginAttemptService;
    @InjectMocks
    private CustomUserDetailsService userDetailsService;

    @Test
    void loadUserByUsername_차단된_이메일이면_LockedException_발생() {
        // given
        given(loginAttemptService.isEmailBlocked("test@example.com")).willReturn(true);

        // when & then
        assertThatThrownBy(() -> userDetailsService.loadUserByUsername("test@example.com"))
                .isInstanceOf(LockedException.class);
    }

    @Test
    void loadUserByUsername_존재하지_않는_이메일이면_UsernameNotFoundException_발생() {
        // given
        given(loginAttemptService.isEmailBlocked("test@example.com")).willReturn(false);
        given(userRepository.findByEmail("test@example.com")).willReturn(Optional.empty());

        // when & then
        assertThatThrownBy(() -> userDetailsService.loadUserByUsername("test@example.com"))
                .isInstanceOf(UsernameNotFoundException.class);
    }

    @Test
    void loadUserByUsername_SUSPENDED_상태이면_isEnabled_false_반환() {
        // given
        User user = User.builder().email("test@example.com").password("encoded").nickname("nickname").build();
        ReflectionTestUtils.setField(user, "id", UUID.randomUUID());
        user.suspend();

        given(loginAttemptService.isEmailBlocked("test@example.com")).willReturn(false);
        given(userRepository.findByEmail("test@example.com")).willReturn(Optional.of(user));

        // when
        UserDetails userDetails = userDetailsService.loadUserByUsername("test@example.com");

        // then
        assertThat(userDetails.isEnabled()).isFalse();
    }

    @Test
    void loadUserByUsername_WITHDRAWN_상태이면_isAccountNonExpired_false_반환() {
        // given
        User user = User.builder().email("test@example.com").password("encoded").nickname("nickname").build();
        ReflectionTestUtils.setField(user, "id", UUID.randomUUID());
        user.withdraw();

        given(loginAttemptService.isEmailBlocked("test@example.com")).willReturn(false);
        given(userRepository.findByEmail("test@example.com")).willReturn(Optional.of(user));

        // when
        UserDetails userDetails = userDetailsService.loadUserByUsername("test@example.com");

        // then
        assertThat(userDetails.isAccountNonExpired()).isFalse();
    }

    @Test
    void loadUserByUsername_정상_사용자이면_authorities_포함된_UserDetails_반환() {
        // given
        UUID userId = UUID.randomUUID();
        User user = User.builder().email("test@example.com").password("encoded").nickname("nickname").build();
        ReflectionTestUtils.setField(user, "id", userId);
        Role role = mock(Role.class);
        given(role.getName()).willReturn("ROLE_USER");
        user.addRole(role);

        given(loginAttemptService.isEmailBlocked("test@example.com")).willReturn(false);
        given(userRepository.findByEmail("test@example.com")).willReturn(Optional.of(user));

        // when
        UserDetails userDetails = userDetailsService.loadUserByUsername("test@example.com");

        // then
        assertThat(userDetails.getUsername()).isEqualTo(userId.toString());
        assertThat(userDetails.isEnabled()).isTrue();
        assertThat(userDetails.isAccountNonExpired()).isTrue();
        assertThat(userDetails.getAuthorities())
                .extracting(GrantedAuthority::getAuthority)
                .containsExactly("ROLE_USER");
    }
}
