/*
 * 클래스 기능 : 다익스트라 알고리즘을 실행하기 위해 사용자로부터 받아야 하는 정보를 담은 클래스
 * 최근 수정 일자 : 2024.02.5(월)
 */
package com.pathfind.system.findPathDto;

import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class GraphVCRequest {
    @NotNull(message = "출발지를 입력해 주세요.")
    private Long start;
    @NotNull(message = "도착지를 입력해 주세요.")
    private Long end;
    @NotEmpty(message = "이동 수단을 선택해 주세요.")
    private String transportation;
}
