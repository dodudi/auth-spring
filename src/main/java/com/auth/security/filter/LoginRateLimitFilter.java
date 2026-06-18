package com.auth.security.filter;

import com.auth.common.exception.ErrorCode;
import com.auth.common.response.ApiResponse;
import com.auth.common.util.HttpUtils;
import com.auth.security.application.LoginAttemptService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;

@RequiredArgsConstructor
public class LoginRateLimitFilter extends OncePerRequestFilter {

    private final LoginAttemptService loginAttemptService;
    private final ObjectMapper objectMapper;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if (isLoginRequest(request)) {
            String ip = HttpUtils.getRealIp(request);
            if (loginAttemptService.isIpBlocked(ip)) {
                response.setContentType("application/json;charset=UTF-8");
                response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
                objectMapper.writeValue(response.getWriter(), ApiResponse.fail(ErrorCode.IP_BLOCKED));
                return;
            }
        }
        filterChain.doFilter(request, response);
    }

    private boolean isLoginRequest(HttpServletRequest request) {
        return "POST".equalsIgnoreCase(request.getMethod()) && "/login".equals(request.getServletPath());
    }
}
