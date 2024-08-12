/*
 * 클래스 기능 : 로그아웃 실패 시 메시지 반환에 쓰이는 dto
 * 최근 수정 일자 : 2024.08.08(목)
 */
package com.pathfind.system.memberDto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class LogoutFailureVCResponse {
    private String message;
}
