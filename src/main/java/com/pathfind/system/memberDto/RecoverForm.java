/*
 * 클래스 기능 : 휴면 계정 복구를 하기 위한 form
 * 최근 수정 일자 : 2024.01.20(토)
 */
package com.pathfind.system.memberDto;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

@Data
public class RecoverForm {

    @NotEmpty(message = "휴면 계정 복구를 위해서는 로그인이 된 상태여야 합니다.")
    private String userId;

}
