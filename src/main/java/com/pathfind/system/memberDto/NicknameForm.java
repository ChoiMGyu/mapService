/*
 * 클래스 기능 : 닉네임 정보를 클라이언트와 컨트롤러 사이에서 주고받기 위해 사용되는 form이다.
 * 최근 수정 일자 : 2024.01.22(월)
 */
package com.pathfind.system.memberDto;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

@Data
public class NicknameForm {
    @NotEmpty(message = "닉네임은 필수입니다.")
    //@Pattern(regexp = "^[ㄱ-ㅎ가-힣a-zA-Z0-9-_]{2,10}$", message = "닉네임은 특수문자를 제외한 2~12자리여야 합니다.")
    private String nickname; //닉네임
}
