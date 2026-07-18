package com.auth.security.handler;

import com.auth.common.response.ApiResponse;
import com.auth.common.util.HttpUtils;
import com.auth.security.application.LoginAttemptService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.jspecify.annotations.NonNull;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;

@Slf4j
@RequiredArgsConstructor
public class JsonAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final ObjectMapper objectMapper;
    private final LoginAttemptService loginAttemptService;
    private final RequestCache requestCache;

    @Override
    public void onAuthenticationSuccess(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull Authentication authentication
    ) throws IOException {
        String ip = HttpUtils.getClientIp(request);
        log.info("[LOGIN_SUCCESS] userId={} ip={}", authentication.getName(), ip);

        String email = request.getParameter("username");
        if (email != null && !email.isBlank()) {
            loginAttemptService.clearFailures(email, ip);
        }

        if (HttpUtils.isJsonRequest(request)) {
            HttpUtils.writeJson(response, objectMapper, HttpServletResponse.SC_OK, ApiResponse.ok());
            return;
        }

        SavedRequest savedRequest = requestCache.getRequest(request, response);
        if (savedRequest != null) {
            requestCache.removeRequest(request, response);
            getRedirectStrategy().sendRedirect(request, response, savedRequest.getRedirectUrl());
            return;
        }

        getRedirectStrategy().sendRedirect(request, response, "/");
    }

}
