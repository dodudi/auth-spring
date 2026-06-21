package com.auth.security.config;

import com.auth.security.application.LoginAttemptService;
import com.auth.security.application.SocialOAuth2UserService;
import com.auth.security.filter.LoginRateLimitFilter;
import com.auth.security.handler.JsonAuthenticationFailureHandler;
import com.auth.security.handler.JsonAuthenticationSuccessHandler;
import com.auth.security.handler.JsonLogoutSuccessHandler;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import tools.jackson.databind.ObjectMapper;

import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${auth.allowed-origins}")
    private String allowedOrigins;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    @Order(3)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http, SocialOAuth2UserService socialOAuth2UserService, ObjectMapper objectMapper, LoginAttemptService loginAttemptService) throws Exception {
        HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
        requestCache.setRequestMatcher(request -> !request.getServletPath().startsWith("/login"));

        JsonAuthenticationSuccessHandler successHandler = new JsonAuthenticationSuccessHandler(objectMapper, loginAttemptService, requestCache);
        JsonAuthenticationFailureHandler failureHandler = new JsonAuthenticationFailureHandler(objectMapper, loginAttemptService);
        LoginRateLimitFilter loginRateLimitFilter = new LoginRateLimitFilter(loginAttemptService, objectMapper);
        JsonLogoutSuccessHandler logoutSuccessHandler = new JsonLogoutSuccessHandler(objectMapper);

        http
                .requestCache(cache -> cache.requestCache(requestCache))
                .addFilterBefore(loginRateLimitFilter, UsernamePasswordAuthenticationFilter.class)
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/oauth/error", "/signup").permitAll()
                        .requestMatchers("/actuator/health", "/actuator/info", "/actuator/prometheus").permitAll()
                        .anyRequest().authenticated()
                )
                .csrf(AbstractHttpConfigurer::disable)
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .successHandler(successHandler)
                        .failureHandler(failureHandler)
                        .permitAll()
                )
                .oauth2Login(oauth2 -> oauth2
                        .loginPage("/login")
                        .successHandler(successHandler)
                        .failureHandler(failureHandler)
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(socialOAuth2UserService)
                        )
                )
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .invalidateHttpSession(true)
                        .deleteCookies("SESSION")
                        .logoutSuccessHandler(logoutSuccessHandler)
                );

        return http.build();
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        Arrays.stream(allowedOrigins.split(","))
                .forEach(config::addAllowedOrigin);
        config.addAllowedMethod("*");
        config.addAllowedHeader("*");
        config.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}
