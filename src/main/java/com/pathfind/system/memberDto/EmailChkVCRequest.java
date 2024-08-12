/*
 * 클래스 기능 : 입력 받은 인증 번호와 발급된 인증 번호가 동일한지 확인하는 DTO
 * 최근 수정 일자 : 2024.08.04(일)
 */
package com.pathfind.system.memberDto;

import com.pathfind.system.validation.ValidationGroups;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

import static com.pathfind.system.validation.ValidationGroups.*;

@Schema(name = "EmailChkVCRequest", description = "입력 받은 인증 번호와 발급된 인증 번호가 동일한지 확인하는 DTO")
@Data
public class EmailChkVCRequest {

    @Schema(name = "email", description = "유저 이메일", example = "qwer1234@mailSvc.abc")
    private String email; //인증 이메일

    @Schema(name = "authNum", description = "입력받는 인증번호")
    @NotEmpty(message = "인증 번호를 입력해주세요.", groups = NotEmptyGroup.class)
    @Pattern(regexp = "^[0-9]*$", message = "인증번호는 숫자만 입력해주세요.", groups = PatternGroup.class)
    private String authNum; //입력받은 인증번호
}
