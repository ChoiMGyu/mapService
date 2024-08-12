/*
 * 클래스 기능 : 예외 발생 enum 클래스
 * 최근 수정 일자 : 2024.08.05(월)
 */
package com.pathfind.system.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ErrorCode implements BasicErrorCode {
    INVALID_INPUT_VALUE(400, "ANY", "INVALID_INPUT", "올바른 값을 입력하지 않은 경우"),
    ROOM_EXCEEDED(403, "", "-403", "방 최대 인원인 5명보다 많은 사람을 초대하는 경우");

    private final int status;
    private final String field;
    private final String code;
    private final String description;

    @Override
    public ErrorReason getErrorReason() {
        return ErrorReason.builder().description(description).code(code).status(status).build();
    }

    @Override
    public ErrorVCResponse getErrorVCResponse() {
        return new ErrorVCResponse("ANY", code, description);
    }
}
