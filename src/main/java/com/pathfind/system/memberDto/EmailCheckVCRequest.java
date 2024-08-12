/*
 * 클래스 기능 : 사용자로부터 받은 이메일 유효성 검증을 위해 사용되는 dto 클래스
 * 최근 수정 일자 : 2024.08.02(금)
 */
package com.pathfind.system.memberDto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

import static com.pathfind.system.validation.ValidationGroups.*;

@Schema(name = "EmailCheckVCRequest", description = "유저 이메일 유효성 검증에 쓰이는 dto")
@Data
public class EmailCheckVCRequest {
    @Schema(name = "email", description = "유저 이메일", example = "qwer1234@mailSvc.abc")
    @NotEmpty(message = "이메일은 필수입니다.", groups = NotEmptyGroup.class)
    @Pattern(regexp = "^(?:\\w+\\.?)*\\w+@(?:\\w+\\.)+\\w+$", message = "이메일 형식이 올바르지 않습니다.", groups = PatternGroup.class)
    private String email; // 유저 아이디
}
