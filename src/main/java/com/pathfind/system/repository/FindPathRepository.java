/*
 * 클래스 기능 :  길찾기 기능을 만들기 위한 repository interface
 * 최근 수정 일자 : 2024.01.27(토)
 */
package com.pathfind.system.repository;

import com.pathfind.system.algorithm.Edge;
import com.pathfind.system.domain.RoadEdge;

import java.util.List;

public interface FindPathRepository {

    public Long getNumVertex();

    public List<RoadEdge> findRoadEdgeAll();
}
