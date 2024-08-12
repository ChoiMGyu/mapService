/*
 * 클래스 기능 : 회원의 아이디와 이메일을 저장하는 dto이다. 길 찾기 방에서 현재 유저 리스트를 표시하기 위해 사용된다.
 * 최근 수정 일자 : 2024.05.29(수)
 */
package com.pathfind.system.findPathService2Dto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class UserInfoVCResponse {
    private String userId;
    private String nickname;
}
