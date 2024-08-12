/*
 * 클래스 기능 : 서비스에서 컨트롤러로의 데이터 전달을 위한 DTO
 * 최근 수정 일자 : 2024.05.25(금)
 */
package com.pathfind.system.findPathDto;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class FindPathCSResponse {
    private double distance;
    private List<VertexInfo> path;
}
