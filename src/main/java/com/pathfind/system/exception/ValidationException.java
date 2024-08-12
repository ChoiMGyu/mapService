/*
 * 클래스 기능 : validation 실패 시 사용하는 exception class
 * 최근 수정 일자 : 2024.07.21(일)
 */
package com.pathfind.system.exception;

import lombok.Getter;

@Getter
public class ValidationException extends CustomException {
    public ValidationException(BasicErrorCode errorCode) {
        super(errorCode, errorCode.getDescription());
    }
}
