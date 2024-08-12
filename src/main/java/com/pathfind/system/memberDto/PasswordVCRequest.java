/*
 * 클래스 기능 : 회원 가입 패스워드 관련 로직 DTO
 * 최근 수정 일자 : 2024.08.02(금)
 */
package com.pathfind.system.memberDto;

import com.pathfind.system.validation.ValidationGroups;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.Data;
import org.hibernate.validator.constraints.Length;

import static com.pathfind.system.validation.ValidationGroups.*;

@Schema(name = "PasswordVCRequest", description = "입력 받은 패스워드와 패스워드 확인을 서버로 전달하는 DTO")
@Data
public class PasswordVCRequest {

    @Schema(name = "password", description = "패스워드")
    @NotEmpty(message = "비밀번호 입력은 필수입니다", groups = NotEmptyGroup.class)
    @Pattern(regexp = "(?=.*[0-9])(?=.*[a-zA-Z])(?=.*\\W)(?=\\S+$).{8,20}", message = "비밀번호는 8~20자 영문 대 소문자, 숫자, 특수문자를 사용하세요.", groups = PatternGroup.class)
    private String password;

    @Schema(name = "passwordConfirm", description = "패스워드 확인")
    private String passwordConfirm;
}
