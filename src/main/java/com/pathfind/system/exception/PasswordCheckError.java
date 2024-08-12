/*
 * 클래스 기능 : 회원 가입 시 패스워드 검증 관련 에러 코드 enum class
 * 최근 수정 일자 : 2024.08.05(월)
 */
package com.pathfind.system.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum PasswordCheckError implements BasicErrorCode {
    NOT_EMPTY(400, "password", "NotEmpty", "비밀번호는 필수입니다."),
    PATTERN(400, "password", "Pattern", "비밀번호는 8~20자 영문 대 소문자, 숫자, 특수문자를 사용하세요."),
    PASSWORD_CONFIRM_EMPTY(409, "passwordConfirm", "PASSWORD_CONFIRM_EMPTY", "비밀번호 확인을 진행해주세요."),
    NOT_SAME(409, "passwordConfirm", "PASSWORD_NOT_SAME", "패스워드가 일치하지 않습니다.");

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
