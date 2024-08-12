/*
 * 클래스 기능 : 길 찾기 경로를 구성하는 정점의 위도, 경도를 담기 위한 Dto
 * 최근 수정 일자 : 2024.05.24(금)
 */
package com.pathfind.system.findPathDto;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class VertexInfo {
    private double Latitude;
    private double Longitude;
}
