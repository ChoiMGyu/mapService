/*
 * 클래스 기능 : 다익스트라 알고리즘 실행 결과를 저장하는 클래스
 * 최근 수정 일자 : 2024.02.05(월)
 */
package com.pathfind.system.algorithm;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class DijkstraResult {
    private List<Node> nodes;
    private List<Integer> path;
}
