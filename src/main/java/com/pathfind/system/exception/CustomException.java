/*
 * 클래스 기능 : custom error exception을 구현한 클래스이다.
 * 최근 수정 일자 : 2024.07.20(토)
 */
package com.pathfind.system.exception;

import lombok.Getter;

@Getter
public class CustomException extends RuntimeException {
    private final BasicErrorCode errorCode;
    private final String message;

    public CustomException(BasicErrorCode errorCode, String message) {
        super(message);
        this.message = message;
        this.errorCode = errorCode;
    }
}
