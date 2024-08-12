/*
 * 클래스 기능 : 길 찾기 서비스(서비스1) interface class
 * 최근 수정 일자 : 2024.05.05(목)
 */
package com.pathfind.system.service;

import com.pathfind.system.findPathDto.FindPathCSResponse;

public interface FindPathService {

    public FindPathCSResponse findSidewalkRoute(Long start, Long end);

    public FindPathCSResponse findRoadRoute(Long start, Long end);
}
