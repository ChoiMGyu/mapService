/*
 * 클래스 기능 : 회원 가입 패스워드 관련 로직 결과 DTO
 * 최근 수정 일자 : 2024.08.02(금)
 */
package com.pathfind.system.memberDto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Schema(name = "PasswordVCResponse", description = "입력 받은 비밀번호와 비밀번호 확인이 일치 여부를 반환하는 DTO")
@Data
@AllArgsConstructor
public class PasswordVCResponse {
    @Schema(name = "passwordCheck", description = "비밀 번호 완료 여부")
    private boolean passwordCheck; //비밀 번호 완료 여부

    @Schema(name = "message", description = "검증 여부에 따라 사용자에게 보여줄 메시지", example = "비밀 번호 확인을 완료하였습니다.")
    private String message;
}
