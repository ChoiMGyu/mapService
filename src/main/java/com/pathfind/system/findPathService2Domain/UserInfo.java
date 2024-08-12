/*
 * 클래스 기능 : 회원의 아이디와 이메일을 저장하는 클래스이다. 길 찾기 방에서 초대 유저 리스트의 정보를 담기 위해 사용된다.
 * 최근 수정 일자 : 2024.05.29(수)
 */
package com.pathfind.system.findPathService2Domain;

import lombok.*;

@Getter
@Setter(AccessLevel.PROTECTED)
@AllArgsConstructor
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserInfo {
    private String userId;
    private String nickname;
}
