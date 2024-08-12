/*
 * 클래스 기능 : 사용자로부터 받은 아이디 유효성 검증을 위해 사용되는 dto 클래스
 * 최근 수정 일자 : 2024.08.02(금)
 */
package com.pathfind.system.memberDto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

import static com.pathfind.system.validation.ValidationGroups.*;

@Schema(name = "UserIdCheckVCRequest", description = "유저 아이디 유효성 검증에 쓰이는 dto")
@Data
public class UserIdCheckVCRequest {
    @Schema(name = "userId", description = "유저 아이디", example = "qwer1234")
    @NotEmpty(message = "아이디는 필수입니다.", groups = NotEmptyGroup.class)
    @Pattern(regexp = "^[0-9a-zA-Z]{5,12}$", message = "아이디는 5~12자 영문 대 소문자, 숫자를 사용하세요.", groups = PatternGroup.class)
    public String userId;
}
