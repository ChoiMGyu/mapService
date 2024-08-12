/*
 * 클래스 기능 : 토큰 생성 후 반환에 쓰이는 dto
 * 최근 수정 일자 : 2024.08.08(목)
 */
package com.pathfind.system.jwtDto;

import lombok.Data;
import lombok.RequiredArgsConstructor;

@Data
@RequiredArgsConstructor
public class IssuedTokenCSResponse {
    private final String accessToken;
    private final String refreshToken;
}
