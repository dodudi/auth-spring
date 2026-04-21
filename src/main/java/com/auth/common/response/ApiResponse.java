package com.auth.common.response;

import com.auth.common.exception.ErrorCode;

public record ApiResponse<T>(
        String code,
        String message,
        T data
) {
    public static <T> ApiResponse<T> ok(T data) {
        return new ApiResponse<>("SUCCESS", "성공", data);
    }

    public static ApiResponse<Void> ok() {
        return new ApiResponse<>("SUCCESS", "성공", null);
    }

    public static ApiResponse<Void> fail(ErrorCode errorCode) {
        return new ApiResponse<>(errorCode.getCode(), errorCode.getMessage(), null);
    }

    public static ApiResponse<Void> fail(ErrorCode errorCode, String message) {
        return new ApiResponse<>(errorCode.getCode(), message, null);
    }
}
