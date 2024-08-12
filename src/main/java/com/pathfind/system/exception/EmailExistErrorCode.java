/*
 * 클래스 기능 : 아이디 찾기 시 이메일 검증 관련 에러 코드 enum class
 * 최근 수정 일자 : 2024.08.05(월)
 */
package com.pathfind.system.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum EmailExistErrorCode implements BasicErrorCode {
    EMAIL_EMPTY(400, "email", "NotEmpty", "이메일은 필수입니다."),
    INVALID_INPUT_VALUE_EMAIL(400, "email", "Pattern", "이메일 형식이 올바르지 않습니다."),
    EMAIL_NOT_EXISTS(409, "email", "EMAIL_NOT_EXIST", "존재하지 않는 이메일입니다.");

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
        return new ErrorVCResponse(field, code, description);
    }
}
