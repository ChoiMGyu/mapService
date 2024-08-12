/*
 * 클래스 기능 : 사용자로부터 받은 이메일 인증번호 유효성 검증을 위해 사용되는 dto 클래스
 * 최근 수정 일자 : 2024.08.03(토)
 */
package com.pathfind.system.memberDto;

import com.pathfind.system.validation.ValidationGroups;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Schema(name = "AuthNumCheckVCRequest", description = "이메일 인증번호 유효성 검증에 쓰이는 dto")
@Data
public class EmailNumberCheckVCRequest {
    @Schema(name = "emailNumber", description = "이메일 인증번호", example = "123456`")
    @NotEmpty(message = "인증 번호를 입력해주세요.", groups = ValidationGroups.NotEmptyGroup.class)
    @Pattern(regexp = "^[0-9]*$", message = "인증번호는 숫자만 입력해주세요.", groups = ValidationGroups.PatternGroup.class)
    private String emailNumber; // 유저 이메일
}
