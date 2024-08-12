/*
 * 클래스 기능 : 아이디 찾기 시 이메일, 이메일 인증 번호 확인에 관한 Error를 정리한 enum class
 * 최근 수정 일자 : 2024.08.05(월)
 */
package com.pathfind.system.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum FindUserIdErrorCode implements BasicErrorCode {
    EMAIL_EMPTY(400, "email", "NotEmpty", "이메일은 필수입니다."),
    INVALID_INPUT_VALUE_EMAIL(400, "email", "Pattern", "이메일 형식이 올바르지 않습니다."),
    EMAIL_NOT_EXISTS(409, "email", "EMAIL_NOT_EXIST", "존재하지 않는 이메일입니다."),
    AUTH_NUM_EMPTY(400, "emailNumber", "NotEmpty", "인증번호를 입력해주세요."),
    INVALID_INPUT_VALUE_AUTH_NUM(400, "emailNumber", "Pattern", "인증번호는 숫자만 입력해주세요."),
    AUTH_NUM_NOT_EXISTS(409, "emailNumber", "AUTH_NUM_NOT_EXIST", "인증번호가 다릅니다.");

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


