/*
 * 클래스 기능 : 컨트롤러에서 뷰로의 데이터 전달을 위한 DTO
 * 최근 수정 일자 : 2024.05.24(금)
 */
package com.pathfind.system.findPathDto;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class ShortestPathVCResponse {
    private double distance;
    private int speed;
    private List<VertexInfo> path;
}
