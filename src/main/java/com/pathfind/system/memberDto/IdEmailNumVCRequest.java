/*
 * 클래스 기능 : 입력한 이메일로 인증번호를 발급하기 위한 DTO
 * 최근 수정 일자 : 2024.08.05(월)
 */
package com.pathfind.system.memberDto;

import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Schema(name = "IdEmailNumVCRequest", description = "유저 아이디, 이메일 유효성, 일치 여부 확인에 쓰이는 dto")
@Data
public class IdEmailNumVCRequest {
    @Schema(name = "userId", description = "유저 아이디", example = "qwer1234")
    @NotEmpty(message = "아이디는 필수입니다")
    @Pattern(regexp = "^[0-9a-zA-Z]{5,12}$", message = "아이디는 5~12자 영문 대 소문자, 숫자를 사용하세요.")
    private String userId;
    @Schema(name = "email", description = "유저 이메일", example = "qwer1234@mailSvc.abc")
    @NotEmpty(message = "이메일은 필수입니다")
    @Pattern(regexp = "^(?:\\w+\\.?)*\\w+@(?:\\w+\\.)+\\w+$", message = "이메일 형식이 올바르지 않습니다.")
    private String email; // 유저 아이디
}
