/*
 * 클래스 기능 : 사용자로부터 받은 이메일 유효성 검증 및 중복 확인을 위해 사용되는 dto 클래스
 * 최근 수정 일자 : 2024.08.05(월)
 */
package com.pathfind.system.memberDto;

import com.pathfind.system.validation.ValidationGroups;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Schema(name = "EmailExistVCRequest", description = "유저 이메일 유효성 검증 및 중복 확인에 쓰이는 dto")
@Data
public class EmailExistVCRequest {
    @Schema(name = "email", description = "유저 이메일", example = "qwer1234@mailSvc.abc")
    @NotEmpty(message = "이메일은 필수입니다")
    @Pattern(regexp = "^(?:\\w+\\.?)*\\w+@(?:\\w+\\.)+\\w+$", message = "이메일 형식이 올바르지 않습니다.")
    private String email; // 유저 아이디
}
