/*
 * 클래스 기능 : 그래프의 정점을 구현한 클래스
 * 최근 수정 일자 : 2024.05.24(금)
 */
package com.pathfind.system.algorithm;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class Node {
    private Long id;
    private double distance;
    private boolean isInfoVertex;
}
