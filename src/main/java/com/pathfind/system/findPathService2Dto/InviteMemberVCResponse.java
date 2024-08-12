/*
 * 클래스 기능 : 길 찾기 방의 회원 초대 성공 여부, 메시지를 View로 전달하기 위해 사용되는 dto 이다.
 * 최근 수정 일자 : 2024.03.18(월)
 */
package com.pathfind.system.findPathService2Dto;

import lombok.*;

@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
@AllArgsConstructor
public class InviteMemberVCResponse {
    private InviteType inviteType;
    private String message;
}
