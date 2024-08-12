/*
 * 클래스 기능 : 길 찾기 방의 회원 초대 요청에 사용되는 dto 이다.
 * 최근 수정 일자 : 2024.05.28(화)
 */
package com.pathfind.system.findPathService2Dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import lombok.Data;

@Data
public class InviteMemberVCRequest {
    @NotBlank(message = "방 아이디는 필수입니다.")
    private String roomId;

    @Pattern(regexp = "^[ㄱ-ㅎ가-힣a-zA-Z0-9-_\\s]{2,12}$", message = "닉네임은 특수문자를 제외한 2~12자리여야 합니다.")
    private String nickname;
}
