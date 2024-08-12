package com.pathfind.system.repository;

import com.pathfind.system.domain.SidewalkEdge;
import jakarta.persistence.EntityManager;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
@RequiredArgsConstructor
public class SidewalkEdgeRepositoryImpl implements SidewalkEdgeRepository {

    private static final Logger logger = LoggerFactory.getLogger(SidewalkEdgeRepositoryImpl.class);

    private final EntityManager em;
    @Override
    public List<SidewalkEdge> findAll() {
        //logger.info("모든 도보 간선을 반환");
        return em.createQuery("select se from SidewalkEdge se", SidewalkEdge.class)
                .getResultList();
    }
}
