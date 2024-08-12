/*
 * 클래스 기능 : 닉네임 유효성 검증 통과 여부를 반환하는데 쓰이는 dto 클래스
 * 최근 수정 일자 : 2024.07.20(토)
 */
package com.pathfind.system.memberDto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Schema(name = "NicknameVCResponse", description = "유저 닉네임 유효성 검증 통과 여부 반환에 쓰이는 dto")
@Data
@AllArgsConstructor
public class NicknameCheckVCResponse {
    @Schema(name = "NicknameCheck", description = "유저 닉네임 유효성 검증 여부", example = "true")
    private boolean NicknameCheck; // 닉네임 유효성 검증 여부
    @Schema(name = "message", description = "검증 여부에 따라 사용자에게 보여줄 메시지", example = "닉네임 중복 확인을 통과하였습니다.")
    private String message;
}
