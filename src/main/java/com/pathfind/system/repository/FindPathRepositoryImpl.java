/*
 * 클래스 기능 :  길찾기 기능을 만들기 위한 repository
 * 최근 수정 일자 : 2024.01.27(토)
 */
package com.pathfind.system.repository;

import com.pathfind.system.algorithm.Edge;
import com.pathfind.system.domain.Member;
import com.pathfind.system.domain.RoadEdge;
import com.pathfind.system.domain.RoadVertex;
import com.pathfind.system.service.MemberServiceImpl;
import jakarta.persistence.EntityManager;
import jakarta.persistence.Query;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

import java.util.LinkedList;
import java.util.List;

@Repository
@RequiredArgsConstructor
public class FindPathRepositoryImpl implements FindPathRepository {

    private static final Logger logger = LoggerFactory.getLogger(FindPathRepositoryImpl.class);

    private final EntityManager em;

    @Override
    public Long getNumVertex() {
        logger.info("도로 정점의 개수를 반환");
        return em.createQuery("select count(rv) from RoadVertex rv", Long.class).getSingleResult();
    }

    @Override
    public List<RoadEdge> findRoadEdgeAll() {
        //logger.info("모든 간선을 반환");
        List<RoadEdge> edgeList = em.createQuery("select re from RoadEdge re", RoadEdge.class).getResultList();
        return edgeList;
    }
}
