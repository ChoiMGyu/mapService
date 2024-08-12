/*
 * 클래스 기능 : 아이디 찾기 성공 시 데이터를 담아 보내는 DTO 클래스
 * 최근 수정 일자 : 2024.08.03(토)
 */
package com.pathfind.system.memberDto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Schema(name = "FindUserIdVCResponse", description = "아이디 찾기 성공 시 데이터를 담아 보내는 DTO")
@Data
@AllArgsConstructor
public class FindUserIdVCResponse {
    @Schema(name = "isRecoverySuccess", description = "아이디 찾기 성공 여부", example = "true")
    private boolean isRecoverySuccess;
    @Schema(name = "userId", description = "유저 아이디", example = "qwer1234")
    private String userId;
    @Schema(name = "message", description = "성공 여부에 따라 사용자에게 보여줄 메시지", example = "아이디 찾기에 성공하였습니다.")
    private String message;
}
