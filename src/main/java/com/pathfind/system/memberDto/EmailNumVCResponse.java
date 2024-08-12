/*
 * 클래스 기능 : 입력한 이메일로 인증번호를 발급하기 위한 DTO
 * 최근 수정 일자 : 2024.07.22(월)
 */
package com.pathfind.system.memberDto;

import io.swagger.v3.oas.annotations.media.Schema;
import lombok.AllArgsConstructor;
import lombok.Data;

@Schema(name = "EmailNumVCResponse", description = "입력한 이메일로 인증번호를 발급하기 위한 DTO")
@Data
@AllArgsConstructor
public class EmailNumVCResponse {

    @Schema(name = "authNumber", description = "발급된 인증 번호")
    private String authNumber;

    @Schema(name = "timeCount", description = "인증 번호 유효 시간")
    private Long timeCount; //이메일 인증 시간

    @Schema(name = "message", description = "검증 여부에 따라 사용자에게 보여줄 메시지", example = "인증 번호를 해당 이메일로 전송하였습니다.")
    private String message;
}
