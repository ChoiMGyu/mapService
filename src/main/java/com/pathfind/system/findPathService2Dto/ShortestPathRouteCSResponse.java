/*
 * 클래스 기능 : 실시간 길 찾기 경로를 찾아 서비스에서 컨트롤러로 넘겨주기 위해 사용되는 dto이다.
 * 최근 수정 일자 : 2024.05.29(수)
 */
package com.pathfind.system.findPathService2Dto;

import com.pathfind.system.findPathDto.VertexInfo;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.util.List;

@Getter
@AllArgsConstructor
public class ShortestPathRouteCSResponse {
    private String userId;
    private double distance;
    private List<VertexInfo> route;
}
