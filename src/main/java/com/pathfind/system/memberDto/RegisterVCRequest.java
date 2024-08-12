/*
 * 클래스 기능 : 회원 가입을 위해 마지막 검증을 위한 DTO 클래스
 * 최근 수정 일자 : 2024.08.04(일)
 */
package com.pathfind.system.memberDto;

import com.pathfind.system.validation.ValidationGroups;
import io.swagger.v3.oas.annotations.media.Schema;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Schema(name = "RegisterVCRequest", description = "회원 가입을 위해 입력 받은 정보들을 서버로 전송하는 DTO")
@Data
public class RegisterVCRequest {

    @Schema(name = "userId", description = "유저 아이디", example = "qwer1234")
    @NotEmpty(message = "아이디 필드 오류")
    @Pattern(regexp = "^[0-9a-zA-Z]{5,12}$", message = "아이디 필드 오류")
    private String userId; //아이디

    @Schema(name = "nickname", description = "유저 닉네임", example = "qwer1234")
    @NotEmpty(message = "닉네임 필드 오류")
    @Pattern(regexp = "^[ㄱ-ㅎ가-힣a-zA-Z0-9-_\\s]{2,12}$", message = "닉네임 필드 오류")
    private String nickname; //닉네임

    @Schema(name = "email", description = "유저 이메일", example = "qwer1234@mailSvc.abc")
    @NotEmpty(message = "이메일 필드 오류")
    @Pattern(regexp = "^(?:\\w+\\.?)*\\w+@(?:\\w+\\.)+\\w+$", message = "이메일 필드 오류")
    private String email; //이메일

    @Schema(name = "authNum", description = "입력받는 인증번호")
    @NotEmpty(message = "인증 번호 필드 오류")
    @Pattern(regexp = "^[0-9]*$", message = "인증 번호 필드 오류")
    private String authNum; //입력받은 인증 번호

    @Schema(name = "password", description = "패스워드")
    @NotEmpty(message = "패스워드 필드 오류")
    @Pattern(regexp = "(?=.*[0-9])(?=.*[a-zA-Z])(?=.*\\W)(?=\\S+$).{8,20}", message = "비밀번호 필드 오류")
    private String password; //패스워드

    @Schema(name = "passwordConfirm", description = "패스워드 확인")
    @NotEmpty(message = "패스워드 확인 오류")
    @Pattern(regexp = "(?=.*[0-9])(?=.*[a-zA-Z])(?=.*\\W)(?=\\S+$).{8,20}", message = "비밀번호 필드 오류")
    private String passwordConfirm; //패스워드 확인
}
