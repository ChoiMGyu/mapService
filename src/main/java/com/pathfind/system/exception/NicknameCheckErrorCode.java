/*
 * 클래스 기능 : 회원 가입 시 닉네임 검증 관련 에러 코드 enum class
 * 최근 수정 일자 : 2024.08.05(월)
 */
package com.pathfind.system.exception;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum NicknameCheckErrorCode implements BasicErrorCode {
    NOT_EMPTY(400, "nickname", "NotEmpty", "닉네임은 필수입니다."),
    PATTERN(400, "nickname", "Pattern", "닉네임은 특수문자를 제외한 2~12자리여야 합니다."),
    NICKNAME_ALREADY_EXISTS(409, "nickname", "NICKNAME_EXIST", "이미 존재하는 닉네임입니다.");

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
