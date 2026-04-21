package com.auth.security.application;

import com.auth.user.domain.*;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class SocialOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

    private final DefaultOAuth2UserService delegate = new DefaultOAuth2UserService();
    private final UserRepository userRepository;
    private final SocialAccountRepository socialAccountRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oauth2User = delegate.loadUser(userRequest);

        String registrationId = userRequest.getClientRegistration().getRegistrationId();
        // 제공자마다 고유 식별자 필드명이 다르다 — Google: "sub", GitHub: "id" 등
        String userNameAttributeName = userRequest.getClientRegistration()
                .getProviderDetails().getUserInfoEndpoint().getUserNameAttributeName();

        SocialProvider provider = SocialProvider.valueOf(registrationId.toUpperCase());
        String providerId = String.valueOf((Object) oauth2User.getAttribute(userNameAttributeName));
        String email = extractEmail(oauth2User, registrationId);
        String nickname = extractNickname(oauth2User, registrationId);

        // 기존 소셜 계정 연결 → 동일 이메일 병합 → 신규 생성 순으로 처리
        User user = findOrCreateUser(email, nickname, provider, providerId);
        List<SimpleGrantedAuthority> authorities = user.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName()))
                .toList();

        // 제공자별로 principal name 필드가 달라 authentication.getName()이 일관되지 않는 문제를 방지하기 위해
        // 이메일을 "identifier" 키로 통일해 principal name으로 사용한다
        Map<String, Object> customAttributes = new HashMap<>(oauth2User.getAttributes());
        customAttributes.put("identifier", email);

        return new DefaultOAuth2User(authorities, customAttributes, "identifier");
    }

    private String extractEmail(OAuth2User oauth2User, String registrationId) {
        return switch (registrationId) {
            case "google" -> oauth2User.getAttribute("email");
            default -> throw new OAuth2AuthenticationException("Unsupported provider: " + registrationId);
        };
    }

    private String extractNickname(OAuth2User oauth2User, String registrationId) {
        return switch (registrationId) {
            case "google" -> oauth2User.getAttribute("name");
            default -> throw new OAuth2AuthenticationException("Unsupported provider: " + registrationId);
        };
    }

    private User findOrCreateUser(String email, String nickname, SocialProvider provider, String providerId) {
        return socialAccountRepository.findByProviderAndProviderId(provider, providerId)
                .map(SocialAccount::getUser)
                .orElseGet(() -> {
                    User user = userRepository.findByEmail(email)
                            .orElseGet(() -> createUser(email, nickname));
                    linkSocialAccount(user, provider, providerId);
                    return user;
                });
    }

    private User createUser(String email, String nickname) {
        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new IllegalStateException("ROLE_USER not found"));
        User user = User.builder()
                .email(email)
                .password(passwordEncoder.encode(UUID.randomUUID().toString()))
                .nickname(nickname)
                .build();
        user.addRole(userRole);
        return userRepository.save(user);
    }

    private void linkSocialAccount(User user, SocialProvider provider, String providerId) {
        socialAccountRepository.save(SocialAccount.builder()
                .user(user)
                .provider(provider)
                .providerId(providerId)
                .build());
    }
}
