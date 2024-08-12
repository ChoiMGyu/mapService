/*
 * 클래스 기능 : 회원 가입을 진행하였을 때 반환되는 DTO 클래스
 * 최근 수정 일자 : 2024.08.02(금)
 */
package com.pathfind.system.memberDto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Schema(name = "RegisterVCResponse", description = "입력 받은 정보를 바탕으로 회원 가입 여부를 반환하는 DTO")
@Data
@AllArgsConstructor
public class RegisterVCResponse {

    @Schema(name = "registerCheck", description = "회원 가입 완료 여부")
    private boolean registerCheck; //회원 가입 완료 여부

    @Schema(name = "message", description = "검증 여부에 따라 사용자에게 보여줄 메시지", example = "회원 가입을 완료하였습니다.")
    private String message;
}
