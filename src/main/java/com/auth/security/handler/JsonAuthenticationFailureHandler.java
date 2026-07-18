package com.auth.security.handler;

import com.auth.common.exception.ErrorCode;
import com.auth.common.response.ApiResponse;
import com.auth.common.util.HttpUtils;
import com.auth.security.application.LoginAttemptService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import tools.jackson.databind.ObjectMapper;
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
        String ip = HttpUtils.getClientIp(request);
        String email = request.getParameter("username");
        log.warn("[LOGIN_FAILURE] email={} ip={} reason={}", email != null ? email : "-", ip, exception.getMessage());

        ErrorCode errorCode;
        if (exception instanceof LockedException) {
            errorCode = ErrorCode.ACCOUNT_LOCKED;
        } else if (exception instanceof DisabledException) {
            errorCode = ErrorCode.ACCOUNT_SUSPENDED;
        } else if (exception instanceof AccountExpiredException) {
            errorCode = ErrorCode.ACCOUNT_WITHDRAWN;
        } else {
            if (email != null && !email.isBlank()) {
                loginAttemptService.recordFailure(email, ip);
            }
            errorCode = ErrorCode.INVALID_CREDENTIALS;
        }

        String accept = request.getHeader("Accept");
        if (accept != null && accept.contains("application/json")) {
            HttpUtils.writeJson(response, objectMapper, errorCode.getHttpStatus().value(), ApiResponse.fail(errorCode));
            return;
        }

        request.getSession().setAttribute("LOGIN_ERROR_CODE", errorCode.getCode());
        response.sendRedirect("/login?error");
    }

}
