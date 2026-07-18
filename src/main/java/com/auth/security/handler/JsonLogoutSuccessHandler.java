package com.auth.security.handler;

import com.auth.common.response.ApiResponse;
import com.auth.common.util.HttpUtils;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JsonLogoutSuccessHandler implements LogoutSuccessHandler {

    private final ObjectMapper objectMapper;

    @Override
    public void onLogoutSuccess(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            Authentication authentication
    ) throws IOException {
        if (authentication != null) {
            log.info("[LOGOUT] userId={} ip={}", authentication.getName(), HttpUtils.getClientIp(request));
        }

        String accept = request.getHeader("Accept");
        if (accept != null && accept.contains("application/json")) {
            HttpUtils.writeJson(response, objectMapper, HttpServletResponse.SC_OK, ApiResponse.ok());
            return;
        }

        response.sendRedirect("/login");
    }
}
