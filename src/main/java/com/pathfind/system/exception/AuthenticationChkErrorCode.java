/*
 * 클래스 기능 : 회원 가입 시 인증 번호 확인에 관한 Error를 정리한 enum class
 * 최근 수정 일자 : 2024.08.05(월)
 */
package com.pathfind.system.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum AuthenticationChkErrorCode implements BasicErrorCode {
    NOT_EMPTY(400, "emailNumber", "NotEmpty", "인증 번호를 입력해주세요."),
    PATTERN(400, "emailNumber", "Pattern", "인증번호는 숫자만 입력해주세요."),
    //CHANGE_EMAIL(409, "emailNumber", "CHANGE_EMAIL", "인증 번호를 재발급 해주세요."),
    CHANGE_AUTHNUM(409, "emailNumber", "CHANGE_AUTHNUM", "입력하신 인증 번호가 일치하지 않습니다."),
    TIME_OUT(409, "emailNumber", "TIME_OUT", "인증 번호 유효 시간이 초과되어 다시 인증 번호를 발급해 주세요."),
    NOT_SAME(409, "emailNumber", "AUTH_NOT_SAME", "입력하신 인증 번호가 일치하지 않습니다.");

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


