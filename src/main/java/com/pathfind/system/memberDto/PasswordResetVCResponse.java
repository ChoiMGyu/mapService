/*
 * 클래스 기능 : 아이디, 이메일, 이메일 인증 번호의 유효성, 일치 여부를 반환하는데 쓰이는 dto 클래스
 * 최근 수정 일자 : 2024.08.05(월)
 */
package com.pathfind.system.memberDto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Schema(name = "PasswordResetVCResponse", description = "유저 아이디, 이메일, 이메일 인증 번호의 유효성, 일치 여부 반환에 쓰이는 dto")
@Data
@AllArgsConstructor
public class PasswordResetVCResponse {
    /*@Schema(name = "UserIdCheck", description = "유저 아이디 유효성 검증 여부", example = "true")
    private boolean UserIdCheck; // 아이디 유효성 검증 여부
    @Schema(name = "EmailCheck", description = "유저 이메일 유효성 검증 여부", example = "true")
    private boolean EmailCheck; // 이메일 유효성 검증 여부
    @Schema(name = "emailNumberCheck", description = "인증 번호 검증 여부")
    private boolean emailNumberCheck; //이메일 인증 번호 검증 여부*/
    @Schema(name = "isRecoverySuccess", description = "비밀번호 초기화 성공 여부", example = "true")
    private boolean isRecoverySuccess;
    @Schema(name = "message", description = "성공 여부에 따라 사용자에게 보여줄 메시지", example = "회원 정보 확인을 통과하였습니다.")
    private String message;
}
