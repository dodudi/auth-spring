package com.auth.common.util;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import tools.jackson.databind.ObjectMapper;

import java.io.IOException;

public final class HttpUtils {

    private static final String JSON_CONTENT_TYPE = "application/json;charset=UTF-8";

    private HttpUtils() {}

    public static String getClientIp(HttpServletRequest request) {
        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isBlank()) {
            return xRealIp;
        }
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isBlank()) {
            return xForwardedFor.split(",")[0].trim();
        }
        return request.getRemoteAddr();
    }

    public static void writeJson(HttpServletResponse response, ObjectMapper objectMapper, int status, Object body) throws IOException {
        response.setContentType(JSON_CONTENT_TYPE);
        response.setStatus(status);
        objectMapper.writeValue(response.getWriter(), body);
    }
}
