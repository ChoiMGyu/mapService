/*
 * 클래스 기능 : 입력 받은 인증 번호와 발급된 인증 번호가 동일한지 확인하는 DTO
 * 최근 수정 일자 : 2024.07.22(월)
 */
package com.pathfind.system.memberDto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Schema(name = "EmailChkVCResponse", description = "입력 받은 인증 번호와 발급된 인증 번호가 동일한지 확인하는 DTO")
@Data
@AllArgsConstructor
public class EmailChkVCResponse {

    @Schema(name = "emailNumberCheck", description = "인증 번호 검증 여부")
    private boolean emailNumberCheck; //이메일 인증 번호 검증 여부

    @Schema(name = "message", description = "검증 여부에 따라 사용자에게 보여줄 메시지", example = "인증 번호 확인을 통과하였습니다.")
    private String message;
}
