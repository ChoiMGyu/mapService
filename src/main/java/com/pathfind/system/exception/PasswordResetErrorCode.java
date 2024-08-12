/*
 * 클래스 기능 : 비밀번호 초기화 시 아이디, 이메일, 이메일 인증 번호의 유효성, 일치 여부 검증 관련 에러 코드 enum class
 * 최근 수정 일자 : 2024.08.05(월)
 */
package com.pathfind.system.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum PasswordResetErrorCode implements BasicErrorCode {
    USER_ID_EMPTY(400, "userId", "NotEmpty", "아이디 필수입니다."),
    INVALID_INPUT_VALUE_USER_ID(400, "userId", "Pattern", "아이디는 5~12자 영문 대 소문자, 숫자를 사용하세요."),
    EMAIL_EMPTY(400, "email", "NotEmpty", "이메일은 필수입니다."),
    INVALID_INPUT_VALUE_EMAIL(400, "email", "Pattern", "이메일 형식이 올바르지 않습니다."),
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
