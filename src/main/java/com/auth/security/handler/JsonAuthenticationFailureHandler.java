package com.auth.security.handler;

import com.auth.common.exception.ErrorCode;
import com.auth.common.response.ApiResponse;
import com.auth.common.util.HttpUtils;
import com.auth.security.application.LoginAttemptService;
import tools.jackson.databind.ObjectMapper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JsonAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private final ObjectMapper objectMapper;
    private final LoginAttemptService loginAttemptService;

    @Override
    public void onAuthenticationFailure(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull AuthenticationException exception
    ) throws IOException {
        String ip = HttpUtils.getRealIp(request);
        log.warn("[LOGIN_FAILURE] ip={} reason={}", ip, exception.getMessage());

        if (exception instanceof LockedException) {
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(ErrorCode.ACCOUNT_LOCKED.getHttpStatus().value());
            objectMapper.writeValue(response.getWriter(), ApiResponse.fail(ErrorCode.ACCOUNT_LOCKED));
            return;
        }

        if (exception instanceof DisabledException) {
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(ErrorCode.ACCOUNT_SUSPENDED.getHttpStatus().value());
            objectMapper.writeValue(response.getWriter(), ApiResponse.fail(ErrorCode.ACCOUNT_SUSPENDED));
            return;
        }

        if (exception instanceof AccountExpiredException) {
            response.setContentType("application/json;charset=UTF-8");
            response.setStatus(ErrorCode.ACCOUNT_WITHDRAWN.getHttpStatus().value());
            objectMapper.writeValue(response.getWriter(), ApiResponse.fail(ErrorCode.ACCOUNT_WITHDRAWN));
            return;
        }

        String email = request.getParameter("username");
        if (email != null && !email.isBlank()) {
            loginAttemptService.recordFailure(email, ip);
        }

        response.setContentType("application/json;charset=UTF-8");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        objectMapper.writeValue(response.getWriter(), ApiResponse.fail(ErrorCode.INVALID_CREDENTIALS));
    }

}
